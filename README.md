## Introduction
Simp v3 will be the third version of the **open (S)ecure (I)nstant (M)essaging (P)rotocol** (simp for short)
This time the protocol is written in the Rust programming language and then later the server and the clients are implemented like so in Rust.
There will be a complete specification manual for those who want to make their own clients compliant with the simp v3 protocol and server

## What features will v3 have?
The simp v3 server will have all the features that simp v2 and simp v1 had and also will mostly inherit the same handshake and post-kex communication process

### The features that are inherited from v2 and v1 are:
####Commands
All the previous basic commands have been implemented.
####Authentication
The handshake process has been re-implemented in rust with better security.
####Encryption
All messages are encrypted with AES-GCM/256

#### Handshake process
- Username and password credentials system
- RSA-4096 public key cryptograpghy with pkcs1v15 padding
- AES-GCM/256 encryption for all messages after kex

#### Username check
Usernames in simp v1 and v2 were checked whether they had fit in certain criterias:
- Usernames have to be Alphanumeric and cannot start with a number
- Usernames have to be at most 16 charachters

#### Credentials database
- In simp v1, v2 userdata was saved in a YAML file and was manipulated by the yamlcpp library
- In simp3 we have moved over to an actual database, using the cargo crate `Diesel`.

#### Prevent various bugs
Many bugs can occur in an encrypted instant messaging environment. Such bugs can include:
- Empty messages sent by clients
- Invalid packets sent by clients
- Incorrect handshake by clients
- Sending too many packets
- Invalid usernames
- Clients sending special characters like escape sequences (`\n`, `\r`, etc)
- Sneaking in divider bytes used by the protocol to exploit
-  Overflowing buffers

Many of these bugs were patched on the original simp v1 thanks to the `susrust` tool made by [vivy\_ir_](http://github.com/vivyir "vivy_ir_")
In simp v3 we hope to tackle all of these bugs with a new debugging tool and also taking advatange of Rust's memory safety

### The features that will be newly added to v3:
#### Seperate text channels (WIP)
On default there will be a #main channel that every user is moved to upon joining, when connected to a channel, they will ONLY recieve:
- Incoming channel messages
- Server broadcasts
- Direct messages using /msg
- Command responses

and their messages are sent to the channel they are connected to
They can join new channels using `/join`

#### UUID (Done)
Every new user will have a unique UUID assigned to them, this allows easier manipulation of users with plugins and internal server logic and a cleaner protocol

#### Super secure dictionary-based authentication. (Yet to be implemented)
The new authentication method that we are working on is sort of like crypto wallets method of giving 24 words from a dictionary that the user must keep track of to authenticate. Except, we have considered the inconvenience of having to type 24 words every time, so you would only need to do this once, per device you are on. The dictionary will be saved locally on the user's computer for convenience.

#### More commands (More or less implemented)
        /help <cmd: Command>: receive help about a specific command
        /msg <user: User> <msg: Text>: send a user a private messages
        /glist: global list of the server (/list will list the users in a certain channel)
        /reply <msg: Text>: reply to the latest user you interacted with
        /join <channel: Channel>: join a text channel
        /lock <channel: Channel>: lock a channel, prevent new users from joining
        /create <channel_name: String> [limit: u16] [password: String]: create a new text channel
		// ... and other channel related commands including moderation commands like /channelmute ...
        /kick <user: User> [reason: Text] : kick user
        /ban <user: User> [reason: Text] [duration: Time]: ban user
        /banip <ip: Ip/v4> [reason: Text]: ip-ban
        /mute <user: User> [reason: Text]: mute user
        /tempmute <user: User> <duration: Time> [reason: Text]
        /whitelist:
                <on/off>: toggle whitelist
                <add> <username: Username>: add a whitelisted username
                <remove> <username: WhitelistedUsername>: remove a whitelisted username
        /plugins: Wil list the plugins of the server
#### Plugins (Yet to be implemented)
Will be most likely written in Lua. Plugins can add commands and can listen to events that are evoked by the server itself

##### Example
```lua
function userMessageEvent(e: UserMessageEvent)
```
is a function that listens to the event of a new user message in a certain channel, inside this function we can implement different functionalities
For example, the user can be manipulated like so:
```lua
 if e.getMessageContent() == "shit" then e.getAuthor().kickUser("Inappropriate word!")
```
#### Permission levels and permission groups (Yet to be implemented)
In the user database, for each user there will be a "permissions" node which is a minecraft-like permission list.
