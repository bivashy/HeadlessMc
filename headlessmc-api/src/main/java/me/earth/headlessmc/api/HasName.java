package me.earth.headlessmc.api;

import java.util.List;
import java.util.Queue;
import java.util.regex.Pattern;

/**
 * A type which can be named.
 */
public interface HasName {
    static <T extends HasName> T getByName(String name, Iterable<T> nameables) {
        for (T t : nameables) {
            if (name.equals(t.getName())) {
                return t;
            }
        }

        return null;
    }

    static <T extends HasName> T getByRegex(Pattern regex, Iterable<T> nameables) {
        T best = null;
        for (T t : nameables) {
            if (regex.matcher(t.getName()).find() && (best == null || String.CASE_INSENSITIVE_ORDER.compare(t.getName(), best.getName()) < 0)) {
                best = t;
            }
        }

        return best;
    }

    /**
     * @return the name of this object.
     */
    String getName();

}
