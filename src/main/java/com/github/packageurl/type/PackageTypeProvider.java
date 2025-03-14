/*
 * MIT License
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package com.github.packageurl.type;

import com.github.packageurl.MalformedPackageURLException;
import com.github.packageurl.PackageURL;
import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;

import java.util.Map;

public interface PackageTypeProvider {
    default void validateComponents(@NonNull String type, @Nullable String namespace, @Nullable String name, @Nullable String version, @Nullable Map<String, String> qualifiers, @Nullable String subpath) throws MalformedPackageURLException {

    }

    default @NonNull PackageURL normalizeComponents(@NonNull String type, @Nullable String namespace, @Nullable String name, @Nullable String version, @Nullable Map<String, String> qualifiers, @Nullable String subpath) throws MalformedPackageURLException {
        return new PackageURL(type, namespace, name, version, qualifiers, subpath);
    }

    default @NonNull String getPackageType() {
        String simpleName = getClass().getSimpleName();
        String packageTypeProvider = "PackageTypeProvider$";
        String[] tokens = simpleName.split(packageTypeProvider, 2);

        if (tokens.length != 2) {
            throw new IllegalArgumentException("Invalid class name for package type provider '" + simpleName + "'");
        }

        String type = tokens[0];

        try {
            PackageTypeFactory.validateType(type);
        } catch (MalformedPackageURLException e) {
            throw new IllegalArgumentException("Package type provider name '" + type + "' is not a valid package type");
        }

        return PackageURL.toLowerCase(type);
    }
}
