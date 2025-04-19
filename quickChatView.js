const quickChatView = () => {
          // Sample data object for chats and messages
          const chatData = {
            users: [
              {
                id: 1,
                name: "Alice",
                lastMessage: "Hey, how's it going?",
                messages: [
                  {
                    sender: "Alice",
                    text: "Hey, how's it going?",
                    timestamp: "10:30 AM",
                  },
                  {
                    sender: "You",
                    text: "Pretty good, thanks! How about you?",
                    timestamp: "10:32 AM",
                  },
                ],
              },
              {
                id: 2,
                name: "Bob",
                lastMessage: "See you tomorrow!",
                messages: [
                  {
                    sender: "Bob",
                    text: "Are we meeting tomorrow?",
                    timestamp: "Yesterday",
                  },
                  {
                    sender: "You",
                    text: "Yes, let's meet at 9 AM.",
                    timestamp: "Yesterday",
                  },
                  {
                    sender: "Bob",
                    text: "See you tomorrow!",
                    timestamp: "Yesterday",
                  },
                ],
              },
              {
                id: 3,
                name: "Charlie",
                lastMessage: "Can you send me the file?",
                messages: [
                  {
                    sender: "Charlie",
                    text: "Can you send me the file?",
                    timestamp: "2 days ago",
                  },
                  {
                    sender: "You",
                    text: "Sure, I'll send it now.",
                    timestamp: "2 days ago",
                  },
                ],
              },
            ],
          };
    return chatData;
};

export default quickChatView;