from logging import Logger
from typing import TYPE_CHECKING, List, Callable

from minecraft.networking.packets import Packet, PlayerPositionAndLookPacket
from minecraft.networking.packets.clientbound.play import TimeUpdatePacket, SpawnPlayerPacket, SpawnObjectPacket, RespawnPacket
from minecraft.networking.types import PositionAndLook
from pcrc.packets.s2c import DestroyEntitiesPacket, ChangeGameStatePacket, SpawnLivingEntityPacket
from pcrc.packets.s2c.entity_packet import AbstractEntityPacket
from pcrc.protocol import MobTypeIds

if TYPE_CHECKING:
	from pcrc.recording.recorder import Recorder


class PacketProcessor:
	def __init__(self, recorder: 'Recorder'):
		self.recorder: 'Recorder' = recorder
		self.logger: Logger = recorder.logger
		self.blocked_entity_ids = set()
		self.player_ids = set()
		self.recorded_time_packet = False

	def init(self):
		self.blocked_entity_ids.clear()
		self.player_ids.clear()
		self.recorded_time_packet = False

	def process(self, packet: Packet) -> bool:
		try:
			return self._process(packet)
		except:
			self.logger.error('Error when processing packet {}'.format(packet))
			self.logger.error('Packet id = {}; Packet name = {}'.format(packet.id, type(packet).__name__))
			raise

	def _process(self, packet: Packet) -> bool:
		def filter_bad_packet() -> bool:
			# if packet_name in constant.BAD_PACKETS:
			# 	return False
			return True

		# update PCRC's position
		def process_player_position_and_look() -> bool:
			if isinstance(packet, PlayerPositionAndLookPacket):
				player_x, player_y, player_z = packet.position
				player_yaw, player_pitch = packet.look
				self.recorder.pos = PositionAndLook(x=player_x, y=player_y, z=player_z, yaw=player_yaw, pitch=player_pitch)
				self.logger.info('Set self\'s position to {}'.format(self.recorder.pos))
			return True

		# world time control
		def process_time_update() -> bool:
			if not self.recorded_time_packet:
				self.recorded_time_packet = True
				day_time = self.recorder.get_config('daytime')
				if 0 <= day_time < 24000 and isinstance(packet, TimeUpdatePacket):
					self.logger.info('Set daytime to: ' + str(day_time))
					packet.time_of_day = -day_time  # If negative sun will stop moving at the Math.abs of the time
			return True

		# Weather yeet
		def process_change_game_state() -> bool:
			# Remove weather if configured
			if not self.recorder.get_config('weather') and isinstance(packet, ChangeGameStatePacket):
				if packet.reason in [1, 2, 7, 8]:
					return False
			return True

		# add player id for afk detector and uuid for recording
		def process_spawn_player() -> bool:
			if isinstance(packet, SpawnPlayerPacket):
				entity_id = getattr(packet, 'entity_id')
				uuid = getattr(packet, 'player_UUID')
				if entity_id not in self.player_ids:
					self.player_ids.add(entity_id)
					self.logger.debug('Player spawned, added to player id list, id = {}'.format(entity_id))
				if uuid not in self.recorder.player_uuids:
					self.recorder.player_uuids.append(uuid)
					self.logger.info('Player spawned, added to uuid list, uuid = {}'.format(uuid))
				self.recorder.refresh_player_movement()
			return True

		def process_spawn_entity() -> bool:
			# Keep track of spawned items and their ids
			# check if the spawned is in black list
			if isinstance(packet, (SpawnObjectPacket, SpawnLivingEntityPacket)):
				entity_id = packet.entity_id
				entity_type_id = packet.type_id
				self.logger.debug('Spawned entity: {}'.format(packet))

				entity_name = None
				if self.recorder.get_config('remove_items') and entity_type_id == MobTypeIds.item(packet.context):
					entity_name = 'Item'
				if self.recorder.get_config('remove_bats') and entity_type_id == MobTypeIds.bat(packet.context):
					entity_name = 'Bat'
				if self.recorder.get_config('remove_phantoms') and entity_type_id == MobTypeIds.phantom(packet.context):
					entity_name = 'Phantom'

				if entity_name is not None:
					self.logger.debug('{} spawned but ignore and added to blocked id list, id = {}'.format(entity_name, entity_id))
					self.blocked_entity_ids.add(entity_id)
					return False
			return True

		# Removed destroyed blocked entity's id
		def process_destroy_entities():
			if isinstance(packet, DestroyEntitiesPacket):
				for entity_id in packet.entity_ids:
					if entity_id in self.blocked_entity_ids:
						self.blocked_entity_ids.remove(entity_id)
						self.logger.debug('Entity destroyed, removed from blocked entity id list, id = {}'.format(entity_id))
					if entity_id in self.player_ids:
						self.player_ids.remove(entity_id)
						self.logger.debug('Player destroyed, removed from player id list, id = {}'.format(entity_id))
			return True

		# Detecting player activity to continue recording and remove items or bats
		def process_entity_packets():
			if isinstance(packet, AbstractEntityPacket):
				entity_id = packet.entity_id
				if entity_id in self.player_ids:
					self.recorder.refresh_player_movement()
					self.logger.debug('Update player movement time from {}, triggered by entity id {}'.format(packet, entity_id))
				if entity_id in self.blocked_entity_ids:
					self.logger.debug('Ignored entity packet of blocked entity id {}'.format(entity_id))
					return False
			return True

		# Detecting player activity to continue recording and remove items or bats
		def process_respawn():
			if isinstance(packet, RespawnPacket):
				self.logger.debug('Set recorded_time_packet to False due to player respawn / dimension change')
				self.recorded_time_packet = False
			return True

		processors: List[Callable[[], bool]] = [
			filter_bad_packet,
			process_player_position_and_look,
			process_time_update,
			process_change_game_state,
			process_spawn_player,
			process_spawn_entity,
			process_destroy_entities,
			process_entity_packets,
			process_respawn,
		]

		for processor in processors:
			if not processor():
				return False
		return True