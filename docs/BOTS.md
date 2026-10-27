# English Telegram bots

28: owner management bot. 29: public trial generator. 34: owner/reseller management.
Each role uses a separate BotFather token; Telegram permits only one getUpdates
poller per token. Configure it from the corresponding menu and use private chats.
Root-only files: `/etc/vpnmanager/bot-admin.json`, `bot-trial.json`, `bot-reseller.json`.

Commands:

| Command | Permission / behavior |
| --- | --- |
| `/start`, `/menu`, `/help` | Show English help |
| `/status` | Owner/authorized reseller; session count |
| `/users` | Owner sees managed users; reseller sees its own |
| `/create USER PASSWORD DAYS LIMIT` | Owner/reseller; enforces quota, creates an account |
| `/trial` | Trial bot: one per Telegram user every 24 hours; validity set in menu |
| `/remove USER` | Owner or owning reseller |
| `/password USER PASSWORD` | Owner or owning reseller; minimum 10 characters |
| `/renew USER DAYS` | Owner or owning reseller; renew from today and unlock |
| `/limit USER LIMIT` | Owner or owning reseller; enable limiter in menu 17 |
| `/lock USER`, `/unlock USER` | Owner or owning reseller; locking disconnects sessions |
| `/allow TELEGRAM_ID QUOTA` | Owner only; assign reseller account slots |
| `/revoke TELEGRAM_ID` | Owner only; disable further reseller access |

Passwords in Telegram commands/replies are visible to the participants and Telegram;
choose appropriate credentials. The bot does not log tokens/passwords and does not
allow commands in groups. No payment processing or unreviewed external bot extension
is installed. Reseller revocation removes bot access; existing VPN accounts remain
until the owner locks/removes them.

A trial account's password is generated randomly, delivered to the requester, and
not stored in plaintext on the server. Expiry is enforced by the manager's minute
expiry timer. Optional button themes and the original third-party bot's private
wire formats are not reproduced; all supported commands are listed here.

These bot permissions are tested offline. A real token/chat must be tested on the
user's VPS; automated checks never contact Telegram or send real messages.
