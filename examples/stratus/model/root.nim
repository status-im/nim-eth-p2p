import NimQml, messagelist

QtObject:
  type Root* = ref object of QObject
    messageList*: MessageList
    app: QApplication
    cb: proc()
    doJoin: proc(channel: string)

  proc delete*(self: Root) =
    self.QObject.delete
    self.messageList.delete

  proc setup(self: Root) =
    self.QObject.setup

  proc newRoot*(
      app: QApplication, cb: proc(),
      doJoin: proc(channel: string)): Root =
    new(result)
    result.messageList = newMessageList()
    result.app = app
    result.cb = cb
    result.doJoin = doJoin
    result.setup()

  proc getMessageList(self: Root): QVariant {.slot.} =
    return newQVariant(self.messageList)

  proc onExitTriggered(self: Root) {.slot.} =
    self.app.quit

  proc onTimer(self: Root) {.slot.} =
    self.cb()

  QtProperty[QVariant] messageList:
    read = getMessageList

  proc add*(self: var Root, a, b, c, d: string)  =
    self.messageList.add(a, b, c, d)

  proc join*(self: Root, channel: string) {.slot.} =
    self.doJoin(channel)
