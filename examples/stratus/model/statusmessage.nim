import NimQml

QtObject:
  type StatusMessage* = ref object of QObject
    channel: string
    source: string
    message: string
    time: string

  proc delete*(self: StatusMessage) =
    self.QObject.delete

  proc setup(self: StatusMessage) =
    self.QObject.setup

  proc newStatusMessage*(channel, source, message, time: string): StatusMessage =
    result = StatusMessage(
      channel: channel,
      source: source,
      message: message,
      time: time,
      )
    result.setup

  proc channel*(self: StatusMessage): string {.slot.} =
    self.channel

  QtProperty[string] channel:
    read = channel

  proc source*(self: StatusMessage): string {.slot.} =
    self.source

  QtProperty[string] source:
    read = source

  proc message*(self: StatusMessage): string {.slot.} =
    self.message

  QtProperty[string] message:
    read = message

  proc time*(self: StatusMessage): string {.slot.} =
    self.time

  QtProperty[string] time:
    read = time
