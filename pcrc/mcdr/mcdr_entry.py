import os
import time
from queue import Queue, Empty
from typing import Optional

from mcdreforged.api.decorator import new_thread
from mcdreforged.command.builder.exception import UnknownArgument, UnknownCommand
from mcdreforged.command.builder.nodes.arguments import GreedyText
from mcdreforged.command.builder.nodes.basic import Literal, CommandContext
from mcdreforged.command.command_source import CommandSource, PlayerCommandSource
from mcdreforged.plugin.server_interface import PluginServerInterface, ServerInterface
from mcdreforged.utils.logger import SyncStdoutStreamHandler

import pcrc as pcrc_module
from pcrc.config import Config
from pcrc.input import InputManager
from pcrc.logger import PcrcLogger
from pcrc.mcdr.mcdr_config import McdrConfig
from pcrc.pcrc_client import PcrcClient

psi = ServerInterface.get_instance().as_plugin_server_interface()
logger = PcrcLogger()
config: McdrConfig = None
user_inputs = Queue()
pcrc_config: Config = None
pcrc_clients: dict[str, "McdrPCRCClient"] = {}


class McdrPCRCClient(PcrcClient):
    def __init__(self, *args, start_source: CommandSource, **kwargs):
        super().__init__(*args, **kwargs)

        self.start_source = start_source


class MCDRInputManager(InputManager[McdrPCRCClient]):
    def input(self, message: str) -> str:
        while True:
            try:
                user_inputs.get_nowait()
            except Empty:
                break
        if isinstance(self.client.start_source, PlayerCommandSource):
            self.client.start_source.reply(
                "Check server console for PCRC to login with microsoft"
            )
        psi.logger.info(
            "Use command `!!PCRC set_redirect_url <url>` to input the redirected url"
        )
        return user_inputs.get()


def create_new_pcrc(source: CommandSource, pcrc_id: str):
    pcrc = McdrPCRCClient(
        id=pcrc_id,
        logger=logger,
        start_source=source,
        input_manager=MCDRInputManager,
    )
    log = pcrc.logger

    log.set_console_handler(SyncStdoutStreamHandler())
    pcrc_id = id(pcrc)
    log.set_console_logging_prefix(
        f"PCRC@{hex((pcrc_id >> 16) & (pcrc_id & 0xFFFF))[2:].rjust(4, '0')}"
    )
    pcrc.reload_config()
    pcrc_clients[pcrc_id] = pcrc

    new_thread(f"PCRC init@{pcrc_id}")(pcrc.init)()

    return pcrc


def on_load(server: PluginServerInterface, old):
    # tweaks_pcrc_constants
    def modify_based_dir(file_path: str) -> str:
        return os.path.join(psi.get_data_folder(), os.path.basename(file_path))

    import pcrc.config as pcrc_config
    from pcrc.connection import pcrc_authentication

    pcrc_config.CONFIG_FILE = modify_based_dir(pcrc_config.CONFIG_FILE)
    pcrc_authentication.SAVED_TOKEN_FILE = modify_based_dir(
        pcrc_authentication.SAVED_TOKEN_FILE
    )

    # register command
    reload_config(None)

    def set_redirect_url(source: CommandSource, context: CommandContext):
        user_inputs.put_nowait(context["url"])

    server.register_command(
        Literal("!!PCRC")
        .requires(lambda src: src.has_permission(config.permission_required))
        .on_error(UnknownCommand, lambda: 0, handled=True)
        .on_error(UnknownArgument, lambda: 0, handled=True)
        .then(Literal("start").runs(start_pcrc).then(GreedyText("id").runs(start_pcrc)))
        .then(Literal("stop").runs(stop_pcrc).then(GreedyText("id").runs(stop_pcrc)))
        .then(Literal("reload").runs(reload_config))
        .then(Literal("list").runs(show_list))
        .then(
            Literal("set_redirect_url").then(GreedyText("url").runs(set_redirect_url))
        )
    )


def show_list(source: CommandSource):
    source.reply("PCRC clients:")
    for index, (id, pcrc) in enumerate(pcrc_clients.items()):
        source.reply(f"  {index}. -> {id} [{'錄製中' if pcrc.is_stopping() else '停止'}]")


def reload_config(source: Optional[CommandSource]):
    global config
    config = psi.load_config_simple("mcdr_config.json", target_class=McdrConfig)

    if source is not None:
        source.reply("PCRC config reloaded")


@new_thread("PCRC Connect")
def start_pcrc(source: CommandSource, ctx: dict[str, str]):
    id = ctx.get("id", "default")

    if id == "all":
        source.reply("all 為保留字，請勿使用")
        return

    if pcrc := pcrc_clients.get(id):
        if pcrc.is_online():
            source.reply(
                "PCRC 已經啟動，請使用 `!!PCRC stop"
                f"{'' if id == 'default' else ' ' + id}` 來停止 PCRC"
            )
        else:
            pcrc.start()
        return

    pcrc = create_new_pcrc(source, id)

    timeout = time.time() + 20
    while timeout > time.time():
        if pcrc.start():
            source.reply("PCRC started")
            break

    if not pcrc.start():
        source.reply("PCRC failed to start, check console for more information")


def stop_pcrc(source: CommandSource, ctx: dict[str, str]):
    id = ctx.get("id", "default")

    if id == "all":
        source.reply("正在停止所有 PCRC")
        for pcrc in pcrc_clients.values():
            if pcrc.is_running():
                pcrc.stop(callback=lambda: cleanup(pcrc))
        return

    pcrc = pcrc_clients.get(id)
    if pcrc is None or pcrc.is_stopping():
        source.reply(f"{id} 尚未啟動")
        return

    # for players, the bot is able to handle `!!PCRC stop` command itself
    if source.is_console:
        source.reply("Stopping PCRC")
        pcrc.stop(callback=lambda: cleanup(pcrc))


def cleanup(pcrc: PcrcClient):
    pcrc.discard()

    if pcrc.id in pcrc_clients:
        del pcrc_clients[pcrc.id]


def on_unload(server: PluginServerInterface):
    for pcrc in pcrc_clients.values():
        _cleanup = lambda: cleanup(pcrc)

        if pcrc.is_running():
            pcrc.stop(callback=_cleanup)
        else:
            _cleanup()

    logger.close_file()
    pcrc_module.pop_pycraft_lib_path()


def on_mcdr_stop(server: PluginServerInterface):
    for id, pcrc in pcrc_clients.items():
        if pcrc.is_running():
            if not pcrc.is_stopping():
                pcrc.stop(block=True)
            for _ in range(60 * 10):
                if pcrc.is_running():
                    server.logger.info(f"Waiting for PCRC@{id} to stop")
                    for _ in range(10):
                        if pcrc.is_running():
                            time.sleep(0.1)
            if pcrc.is_running():
                server.logger.info(
                    f"PCRC@{id} took too long to stop (more than 10min)! Exit anyway"
                )

        cleanup(pcrc)

    logger.close_file()
