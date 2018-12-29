import QtQuick 2.3
import QtQuick.Controls 1.3
import QtQuick.Controls 2.3
import QtQuick.Layouts 1.3

ApplicationWindow {
    width: 1600
    height: 1050
    title: "Stratus"
    visible: true

    function joinChannel() {
        root.join(channelTextField.text)
        joinedChannels.append({"name": channelTextField.text})
        channelTextField.text = ""
    }

    function sendMessage() {
        messageTextField.text = "haha. you thought this actually worked? go fix it!"
    }

    Timer {
        interval: 50; running: true; repeat: true
        onTriggered: root.onTimer()
    }

    ListModel {
        id: joinedChannels
        // ListElement { name: "test" }
    }

    SplitView {
        anchors.fill: parent
        orientation: Qt.Horizontal

        Item {
            width: parent.width * 0.25

            ColumnLayout {
                anchors.margins: 5
                anchors.fill: parent
                spacing: 5

                ListView {
                    model: joinedChannels
                    Layout.fillHeight: true

                    delegate: Row {
                        spacing: 0
                        Text { text: name[0].toUpperCase(); font.pointSize: 24; font.bold: true; width: height ; horizontalAlignment: Text.AlignHCenter; verticalAlignment: Text.AlignVCenter; anchors.verticalCenter: parent.verticalCenter }
                        Text { text: "#"; font.pointSize: 16; verticalAlignment: Text.AlignVCenter; anchors.verticalCenter: parent.verticalCenter }
                        Text { text: name; font.pointSize: 16; verticalAlignment: Text.AlignVCenter; anchors.verticalCenter: parent.verticalCenter }
                    }
                }

                RowLayout {
                    Text { text: "#"; font.pointSize: 16 }
                    TextField { id: channelTextField; Layout.fillWidth: true; onAccepted: joinChannel() }

                    Button {
                        id: joinButton
                        text: "Join channel"
                        onClicked: joinChannel()
                        enabled: channelTextField.text != ""
                    }
                }
            }
        }

        Item {
            Layout.fillWidth: true

            ColumnLayout {
                anchors.margins: 5
                anchors.fill: parent

                ListModel {
                    id: sampleMessages
                    ListElement {
                        channel: "test"
                        source: "xxx"
                        time: "1212"
                        message: "message that is really really long xxxxXXXXxxsacdsca asdcasd cas cdad casd cascdsa ad sadcasd csad csad csadmessage that is really really long xxxxXXXXxxsacdsca asdcasd cas cdad casd cascdsa ad sadcasd csad csad csad"
                    }
                    ListElement {
                        channel: "test"
                        source: "xxx"
                        time: "1212"
                        message: "message that is really really long"
                    }
                    ListElement {
                        channel: "test"
                        source: "xxx"
                        time: "1212"
                        message: "message that is really really long xxxxXXXXxxsacdsca asdcasd cas cdad casd cascdsa ad sadcasd csad csad csadmessage that is really really long xxxxXXXXxxsacdsca asdcasd cas cdad casd cascdsa ad sadcasd csad csad csad"
                    }
                }

                ListView {
                    id: messagesView
                    model: root.messageList
                    // model: sampleMessages
                    Layout.fillWidth: true
                    Layout.fillHeight: true
                    delegate: RowLayout {
                        width: messagesView.width
                        Text { text: "👾"; font.pointSize: 28 }

                        ColumnLayout {
                            Layout.fillWidth: true
                            RowLayout {
                                Text { text: channel; font.bold: true }
                                Text { text: " ("; }
                                Text { text: source; }
                                Text { text: ")"; }
                                Item { Layout.fillWidth: true }
                                Text { text: time; }
                            }

                            Text { Layout.fillWidth: true; text: message; wrapMode: Text.WordWrap }
                        }
                    }
                }

                RowLayout {
                    TextField {
                        id: messageTextField;
                        Layout.fillWidth: true;
                        onAccepted: sendMessage()
                    }

                    Button {
                        id: sendButton
                        text: "Send"
                        onClicked: sendMessage()
                        enabled: messageTextField.text != ""
                    }
                }
            }
        }
    }
}
