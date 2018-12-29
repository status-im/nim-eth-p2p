import NimQml, statusmessage, Tables

type
  StatusMessageRoles {.pure.} = enum
    Channel = UserRole + 1
    Source = UserRole + 2
    Message = UserRole + 3
    Time = UserRole + 4

QtObject:
  type
    MessageList* = ref object of QAbstractListModel
      messages*: seq[StatusMessage]

  proc delete(self: MessageList) =
    self.QAbstractListModel.delete
    for message in self.messages:
      message.delete
    self.messages = @[]

  proc setup(self: MessageList) =
    self.QAbstractListModel.setup

  proc newMessageList*(): MessageList =
    new(result, delete)
    result.messages = @[]
    result.setup

  method rowCount(self: MessageList, index: QModelIndex = nil): int =
    return self.messages.len

  method data(self: MessageList, index: QModelIndex, role: int): QVariant =
    if not index.isValid:
      return
    if index.row < 0 or index.row >= self.messages.len:
      return
    let message = self.messages[index.row]
    let messageRole = role.StatusMessageRoles
    case messageRole:
      of StatusMessageRoles.Channel: result = newQVariant(message.channel)
      of StatusMessageRoles.Source: result = newQVariant(message.source)
      of StatusMessageRoles.Message: result = newQVariant(message.message)
      of StatusMessageRoles.Time: result = newQVariant(message.time)
      else: return

  method roleNames(self: MessageList): Table[int, string] =
    { StatusMessageRoles.Channel.int:"channel",
      StatusMessageRoles.Source.int:"source",
      StatusMessageRoles.Message.int:"message",
      StatusMessageRoles.Time.int:"time"}.toTable

  proc add*(
      self: MessageList, channel: string, source: string, message: string,
      time: string) {.slot.} =
    let sm = newStatusMessage(channel, source, message, time)

    self.beginInsertRows(newQModelIndex(), self.messages.len, self.messages.len)
    self.messages.add(sm)
    self.endInsertRows()

  proc del*(self: MessageList, pos: int) {.slot.} =
    if pos < 0 or pos >= self.messages.len:
      return
    self.beginRemoveRows(newQModelIndex(), pos, pos)
    self.messages.del(pos)
    self.endRemoveRows
