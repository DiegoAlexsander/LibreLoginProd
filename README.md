

# Maintenance update 🚀 ❗❗❗minecraft 1.21.10

After couple of weeks I've decided to make a move towards new login plugin which is currently under development.
I'm not going to maintain this plugin anymore, but still I'm open to PR's with 1.21.10 support.
Here's the new plugin repo: https://github.com/Navio1430/NavAuth. I'm open to literally any support (even by leaving a star) with code, docs, ideas etc. also anything from todo's list.

<br><br>
<br><br>
<div display="flex" justify-content="space-between" align="center">
 <h1>LibreLoginProd 🔐 - autologin plugin</h1>
  <p>Fork of the <b>LibreLogin</b> (previously LibrePremium) which has caused many problems with newest minecraft versions.
LibreLogin did not meet our expectations, which is why this fork was created.</p>
</div>
<br>
<br>

# Quick information 📌

<img src="https://img.shields.io/badge/Java%20version-%2017+-blue?style=for-the-badge&logo=java&logoColor=white"
alt="Plugin requires Java 17 or newer"></img>
<a href="https://discord.gg/WTtEQneRJb">
<img src="https://img.shields.io/badge/Discord-%20SUPPORT-purple?style=for-the-badge&logo=discord&logoColor=white" 
alt="Support available on Discord"></img>
</a>
<a href="https://github.com/Navio1430/LibreLoginProd/graphs/contributors">
<img src="https://img.shields.io/badge/Contributors-Credits-blue?style=for-the-badge" 
alt="Contributors listed"></img>
</a>

<a href="https://github.com/Navio1430/LibreLoginProd/wiki">
<img src="https://img.shields.io/badge/Documentation-Docs-orange?style=for-the-badge&logo=wikipedia" alt="Documentation on the Wiki"></img>
</a>

## Basic set of features 🎯

- AutoLogin for premium players
- TOTP 2FA (Authy, Google Authenticator...) [details](https://github.com/Navio1430/LibreLoginProd/wiki/2FA)
- Session system
- Name validation (including case sensitivity check)
- Automatic data migration for premium players
- Migration of a player's data by using one command
- Geyser (Bedrock) support using [Floodgate](https://github.com/Navio1430/LibreLoginProd/wiki/Floodgate)

## Platforms ⚙️
- [✔️] Velocity - up to 1.21.8
- [✔️] Paper - up to 1.21.8
- [❌] BungeeCord - no longer supported, do not use it for production

## Main changes 

- [📚] Support for the newest Minecraft Paper and Velocity versions

- [❌] No more support for BungeeCord (maybe will be brought back in future)
- [❌] Removed compatibility with NanoLimboPlugin (should not be used on prod)

# FAQ

### What does prod mean?
This means that the project is a heavily modified version intended for production use.

### Why is the plugin almost 5MB?
We are currently trying to go down to 500KB, but first we need
to divide whole project into submodules.

### Will the folder name change after installation?
No, we use the same folder and config names as original the **LibreLogin**.

# License

Project is licensed under the Mozilla Public License 2.0.
[Read the license here.](https://github.com/Navio1430/LibreLoginProd/blob/master/LICENSE)
