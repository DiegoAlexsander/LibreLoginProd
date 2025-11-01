/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 */

package xyz.kyngs.librelogin.common.command;

import co.aikar.commands.CommandManager;
import co.aikar.commands.MessageKeys;
import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.util.HashMap;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import net.kyori.adventure.audience.Audience;
import net.kyori.adventure.text.TextComponent;
import net.kyori.adventure.text.serializer.legacy.LegacyComponentSerializer;
import xyz.kyngs.librelogin.api.database.User;
import xyz.kyngs.librelogin.common.AuthenticHandler;
import xyz.kyngs.librelogin.common.AuthenticLibreLogin;
import xyz.kyngs.librelogin.common.command.commands.ChangePasswordCommand;
import xyz.kyngs.librelogin.common.command.commands.authorization.LoginCommand;
import xyz.kyngs.librelogin.common.command.commands.authorization.RegisterCommand;
import xyz.kyngs.librelogin.common.command.commands.mail.ConfirmPasswordReset;
import xyz.kyngs.librelogin.common.command.commands.mail.ResetPasswordViaEMailCommand;
import xyz.kyngs.librelogin.common.command.commands.mail.SetEMailCommand;
import xyz.kyngs.librelogin.common.command.commands.mail.VerifyEMailCommand;
import xyz.kyngs.librelogin.common.command.commands.premium.PremiumConfirmCommand;
import xyz.kyngs.librelogin.common.command.commands.premium.PremiumDisableCommand;
import xyz.kyngs.librelogin.common.command.commands.premium.PremiumEnableCommand;
import xyz.kyngs.librelogin.common.command.commands.staff.LibreLoginCommand;
import xyz.kyngs.librelogin.common.command.commands.tfa.TwoFactorAuthCommand;
import xyz.kyngs.librelogin.common.command.commands.tfa.TwoFactorConfirmCommand;
import xyz.kyngs.librelogin.common.util.RateLimiter;

public class CommandProvider<P, S> extends AuthenticHandler<P, S> {

    public static final LegacyComponentSerializer ACF_SERIALIZER =
            LegacyComponentSerializer.legacySection();

    private final CommandManager<?, ?, ?, ?, ?, ?> manager;
    private final RateLimiter<UUID> limiter;
    private final Cache<UUID, Object> confirmCache;

    public CommandProvider(AuthenticLibreLogin<P, S> plugin) {
        super(plugin);

        limiter = new RateLimiter<>(1, TimeUnit.SECONDS);

        manager = plugin.provideManager();

        injectMessages();

        var contexts = manager.getCommandContexts();

        contexts.registerIssuerAwareContext(
                Audience.class,
                context -> {
                    if (limiter.tryAndLimit(context.getIssuer().getUniqueId()))
                        throw new xyz.kyngs.librelogin.common.command.InvalidCommandArgument(
                                plugin.getMessages().getMessage("error-throttle"));
                    return plugin.getAudienceFromIssuer(context.getIssuer());
                });

        // Thanks type erasure
        contexts.registerIssuerAwareContext(
                Object.class,
                context -> {
                    var player = plugin.getPlayerFromIssuer(context.getIssuer());

                    if (player == null)
                        throw new co.aikar.commands.InvalidCommandArgument(
                                MessageKeys.NOT_ALLOWED_ON_CONSOLE, false);

                    return player;
                });

        contexts.registerIssuerAwareContext(
                UUID.class,
                context -> {
                    var player = plugin.getPlayerFromIssuer(context.getIssuer());

                    if (player == null)
                        throw new co.aikar.commands.InvalidCommandArgument(
                                MessageKeys.NOT_ALLOWED_ON_CONSOLE, false);

                    return plugin.getPlatformHandle().getUUIDForPlayer(player);
                });

        manager.setDefaultExceptionHandler(
                (command, registeredCommand, sender, args, t) -> {
                    if (!(t
                            instanceof
                            xyz.kyngs.librelogin.common.command.InvalidCommandArgument ourEx)) {
                        var logger = plugin.getLogger();

                        logger.error(
                                "An unexpected exception occurred while performing command, please"
                                        + " attach the stacktrace below and report this issue.");

                        t.printStackTrace();

                        return false;
                    }

                    plugin.getAudienceFromIssuer(sender).sendMessage(ourEx.getUserFuckUp());

                    return true;
                },
                false);

        confirmCache = Caffeine.newBuilder().expireAfterWrite(5, TimeUnit.MINUTES).build();

        manager.registerCommand(new LoginCommand<>(plugin));
        manager.registerCommand(new RegisterCommand<>(plugin));
        
        // Setup configurable aliases - must be called AFTER command registration
        setupCommandAliases();
        
        manager.registerCommand(new PremiumEnableCommand<>(plugin));
        manager.registerCommand(new PremiumConfirmCommand<>(plugin));
        manager.registerCommand(new PremiumDisableCommand<>(plugin));
        manager.registerCommand(new ChangePasswordCommand<>(plugin));
        manager.registerCommand(new LibreLoginCommand<>(plugin));

        if (plugin.getTOTPProvider() != null) {
            manager.registerCommand(new TwoFactorAuthCommand<>(plugin));
            manager.registerCommand(new TwoFactorConfirmCommand<>(plugin));
        }

        if (plugin.getEmailHandler() != null) {
            manager.registerCommand(new SetEMailCommand<>(plugin));
            manager.registerCommand(new VerifyEMailCommand<>(plugin));
            manager.registerCommand(new ResetPasswordViaEMailCommand<>(plugin));
            manager.registerCommand(new ConfirmPasswordReset<>(plugin));
        }
    }

    public void registerConfirm(UUID uuid) {
        confirmCache.put(uuid, new Object());
    }

    public void onConfirm(P player, Audience audience, User user) {
        if (confirmCache.asMap().remove(user.getUuid()) == null)
            throw new InvalidCommandArgument(plugin.getMessages().getMessage("error-no-confirm"));

        audience.sendMessage(plugin.getMessages().getMessage("info-enabling"));

        LibreLoginCommand.enablePremium(player, user, plugin, true);

        plugin.getDatabaseProvider().updateUser(user);

        platformHandle.kick(player, plugin.getMessages().getMessage("kick-premium-info-enabled"));
    }

    public TextComponent getMessage(String key) {
        return plugin.getMessages().getMessage(key);
    }

    private String getMessageAsString(String key) {
        return ACF_SERIALIZER.serialize(getMessage(key));
    }

    public RateLimiter<UUID> getLimiter() {
        return limiter;
    }

    private void setupCommandAliases() {
        // Get configured aliases from config
        var loginAliases =
                plugin.getConfiguration()
                        .get(
                                xyz.kyngs.librelogin.common.config.ConfigurationKeys
                                        .LOGIN_COMMAND_ALIASES);
        var registerAliases =
                plugin.getConfiguration()
                        .get(
                                xyz.kyngs.librelogin.common.config.ConfigurationKeys
                                        .REGISTER_COMMAND_ALIASES);

        // Default aliases hardcoded in @CommandAlias annotations
        var defaultLoginAliases = java.util.Set.of("login", "l", "log");
        var defaultRegisterAliases = java.util.Set.of("register", "reg");

        // Convert configured aliases to sets
        var configuredLoginSet = new java.util.HashSet<>(loginAliases);
        var configuredRegisterSet = new java.util.HashSet<>(registerAliases);

        // Find aliases to remove (in defaults but not in config)
        var disabledLoginAliases = new java.util.HashSet<>(defaultLoginAliases);
        disabledLoginAliases.removeAll(configuredLoginSet);

        var disabledRegisterAliases = new java.util.HashSet<>(defaultRegisterAliases);
        disabledRegisterAliases.removeAll(configuredRegisterSet);

        // Try multiple possible field names for ACF's command registry
        String[] possibleFieldNames = {"rootCommands", "commands", "registeredCommands", "commandMap"};
        boolean success = false;

        for (String fieldName : possibleFieldNames) {
            try {
                var field = manager.getClass().getDeclaredField(fieldName);
                field.setAccessible(true);
                @SuppressWarnings("unchecked")
                var commandsMap = (java.util.Map<String, ?>) field.get(manager);

                // Unregister disabled login aliases
                for (String alias : disabledLoginAliases) {
                    if (commandsMap.remove(alias.toLowerCase(java.util.Locale.ENGLISH)) != null) {
                        plugin.getLogger().info("Unregistered login alias: " + alias);
                    }
                }

                // Unregister disabled register aliases
                for (String alias : disabledRegisterAliases) {
                    if (commandsMap.remove(alias.toLowerCase(java.util.Locale.ENGLISH))
                            != null) {
                        plugin.getLogger().info("Unregistered register alias: " + alias);
                    }
                }

                success = true;
                break; // Found the right field, exit loop

            } catch (NoSuchFieldException e) {
                // Try next field name
                continue;
            } catch (Exception e) {
                plugin.getLogger()
                        .warn(
                                "Error accessing field '"
                                        + fieldName
                                        + "': "
                                        + e.getMessage());
                break;
            }
        }

        if (!success) {
            // Fallback: try to inspect all fields to find the right one
            plugin.getLogger()
                    .warn(
                            "Could not find command registry field. Trying to inspect manager"
                                    + " class...");
            try {
                var allFields = manager.getClass().getDeclaredFields();
                plugin.getLogger().info("Available fields in CommandManager:");
                for (var field : allFields) {
                    plugin.getLogger().info("  - " + field.getName() + " (" + field.getType().getSimpleName() + ")");
                }
            } catch (Exception e) {
                // Ignore
            }

            plugin.getLogger()
                    .warn(
                            "Failed to configure command aliases. All default aliases will remain"
                                + " active.");
            plugin.getLogger()
                    .warn(
                            "To customize aliases, please report the 'Available fields' list"
                                    + " above.");
        } else {
            // Successfully unregistered from ACF
            // Now also unregister from Velocity native CommandManager if running on Velocity
            try {
                // Check if we're running on Velocity by trying to get the ProxyServer
                var velocityClass =
                        Class.forName("xyz.kyngs.librelogin.velocity.VelocityLibreLogin");
                if (velocityClass.isInstance(plugin)) {
                    // We're on Velocity, get the ProxyServer
                    var getServerMethod = velocityClass.getDeclaredMethod("getProxyServer");
                    getServerMethod.setAccessible(true);
                    var proxyServer = getServerMethod.invoke(plugin);

                    // Get Velocity's native CommandManager
                    var proxyServerClass = proxyServer.getClass();
                    var getCommandManagerMethod =
                            proxyServerClass.getMethod("getCommandManager");
                    var velocityCommandManager = getCommandManagerMethod.invoke(proxyServer);

                    // Unregister aliases from Velocity's native CommandManager
                    var unregisterMethod =
                            velocityCommandManager
                                    .getClass()
                                    .getMethod("unregister", String.class);

                    for (String alias : disabledLoginAliases) {
                        unregisterMethod.invoke(
                                velocityCommandManager,
                                alias.toLowerCase(java.util.Locale.ENGLISH));
                        plugin.getLogger()
                                .info(
                                        "Unregistered login alias from Velocity native: "
                                                + alias);
                    }

                    for (String alias : disabledRegisterAliases) {
                        unregisterMethod.invoke(
                                velocityCommandManager,
                                alias.toLowerCase(java.util.Locale.ENGLISH));
                        plugin.getLogger()
                                .info(
                                        "Unregistered register alias from Velocity native: "
                                                + alias);
                    }
                }
            } catch (ClassNotFoundException e) {
                // Not running on Velocity, skip
            } catch (Exception e) {
                plugin.getLogger()
                        .warn(
                                "Failed to unregister from Velocity native CommandManager: "
                                        + e.getMessage());
            }

            // Log active aliases
            if (!configuredLoginSet.isEmpty()) {
                plugin.getLogger()
                        .info(
                                "Active login command aliases: "
                                        + String.join(", ", configuredLoginSet));
            }
            if (!configuredRegisterSet.isEmpty()) {
                plugin.getLogger()
                        .info(
                                "Active register command aliases: "
                                        + String.join(", ", configuredRegisterSet));
            }
        }
    }

    public void injectMessages() {
        var locales = manager.getLocales();
        var localeMap = new HashMap<String, String>();

        localeMap.put("acf-core.permission_denied", getMessageAsString("error-no-permission"));
        localeMap.put(
                "acf-core.permission_denied_parameter", getMessageAsString("error-no-permission"));
        localeMap.put("acf-core.invalid_syntax", getMessageAsString("error-invalid-syntax"));
        localeMap.put("acf-core.unknown_command", getMessageAsString("error-unknown-command"));

        plugin.getMessages()
                .getMessages()
                .forEach(
                        (key, value) -> {
                            if (key.startsWith("syntax")) {
                                localeMap.put(key, ACF_SERIALIZER.serialize(value));
                            } else if (key.startsWith("autocomplete")) {
                                var serialized = ACF_SERIALIZER.serialize(value);
                                manager.getCommandReplacements()
                                        .addReplacement(
                                                key,
                                                serialized.isBlank()
                                                        ? serialized
                                                        : serialized + " @nothing");
                            }
                        });

        locales.addMessageStrings(locales.getDefaultLocale(), localeMap);
    }
}

