package me.earth.headlessmc.launcher;

import me.earth.headlessmc.api.config.Property;
import me.earth.headlessmc.config.HmcProperties;
import me.earth.headlessmc.launcher.files.ConfigService;

import static me.earth.headlessmc.config.PropertyTypes.*;

/**
 * Properties used by the launcher. These can be set as SystemProperties or in
 * the config file managed by the {@link ConfigService}.
 */
public interface LauncherProperties extends HmcProperties {
    Property<String> MC_DIR = string("hmc.mcdir");
    Property<String> GAME_DIR = string("hmc.gamedir");

    Property<String> OS_NAME = string("hmc.osname");
    Property<String> OS_TYPE = string("hmc.ostype");
    Property<String> OS_VERSION = string("hmc.osversion");
    Property<Boolean> OS_ARCH = bool("hmc.osarch");

    Property<String[]> JAVA = array("hmc.java.versions", ";");

    Property<String[]> JVM_ARGS = array("hmc.jvmargs", " ");
    Property<String[]> GAME_ARGS = array("hmc.gameargs", " ");
    Property<String> CLASS_PATH = string("hmc.additional.classpath");
    Property<String> CUSTOM_MAIN_CLASS = string("hmc.main.class");

    Property<String> LAUNCHER_NAME = string("hmc.launchername");
    Property<String> LAUNCHER_VERSION = string("hmc.launcherversion");

    Property<String> EMAIL = string("hmc.email");
    Property<String> PASSWORD = string("hmc.password");
    Property<Boolean> INVERT_OFFLINE_FLAG = bool("hmc.invert.offline.flag");

    Property<Boolean> KEEP_FILES = bool("hmc.keepfiles");
    Property<Boolean> STORE_ACCOUNTS = bool("hmc.store.accounts");

    Property<Boolean> INVERT_LWJGL_FLAG = bool("hmc.invert.lwjgl.flag");
    Property<Boolean> INVERT_PAULS_FLAG = bool("hmc.invert.pauls.flag");
    Property<Boolean> INVERT_QUIT_FLAG = bool("hmc.invert.quit.flag");
    Property<Boolean> INVERT_JNDI_FLAG = bool("hmc.invert.jndi.flag");
    Property<Boolean> INVERT_LOOKUP_FLAG = bool("hmc.invert.lookup.flag");

    Property<Boolean> JOML_NO_UNSAFE = bool("hmc.joml.no.unsafe");

    Property<String> XUID = string("hmc.xuid");
    Property<String> CLIENT_ID = string("hmc.clientId");
    Property<String> USER_PROPERTIES = string("hmc.userproperties");
    Property<String> PROFILE_PROPERTIES = string("hmc.profileproperties");

    Property<String> FABRIC_URL = string("hmc.fabric.url");

}
