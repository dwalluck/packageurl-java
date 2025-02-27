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
package com.github.packageurl;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.TreeMap;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

/**
 * Test cases for PackageURL parsing
 * <p>
 * Original test cases retrieved from:
 * <a href="https://raw.githubusercontent.com/package-url/purl-spec/master/test-suite-data.json">https://raw.githubusercontent.com/package-url/purl-spec/master/test-suite-data.json</a>
 *
 * @author Steve Springett
 */
class PackageURLTest {
    private static JSONArray json = new JSONArray();

    @BeforeAll
    public static void setup() throws IOException {
        try (InputStream is = PackageURLTest.class.getResourceAsStream("/test-suite-data.json")) {
            assertNotNull(is);
            json = new JSONArray(new JSONTokener(is));
        }
    }

    @Test
    void testEncoding1() throws MalformedPackageURLException {
        PackageURL purl = new PackageURL("maven", "com.google.summit", "summit-ast", "2.2.0\n", null, null);
        assertEquals("pkg:maven/com.google.summit/summit-ast@2.2.0%0A", purl.toString());
    }

    @Test
    void testEncoding2() throws MalformedPackageURLException {
        PackageURL purl = new PackageURL("pkg:nuget/%D0%9Cicros%D0%BEft.%D0%95ntit%D1%83Fram%D0%B5work%D0%A1%D0%BEr%D0%B5");
        assertEquals("Мicrosоft.ЕntitуFramеworkСоrе", purl.getName());
        assertEquals("pkg:nuget/%D0%9Cicros%D0%BEft.%D0%95ntit%D1%83Fram%D0%B5work%D0%A1%D0%BEr%D0%B5", purl.toString());
    }

    @Test
    void testConstructorParsing() throws Exception {
        for (int i = 0; i < json.length(); i++) {
            JSONObject testDefinition = json.getJSONObject(i);

            final String purlString = testDefinition.getString("purl");
            final String cpurlString = testDefinition.optString("canonical_purl");
            final boolean invalid = testDefinition.getBoolean("is_invalid");

            System.out.println("Running test on: " + purlString);

            final String type = testDefinition.optString("type", null);
            final String namespace = testDefinition.optString("namespace", null);
            final String name = testDefinition.optString("name", null);
            final String version = testDefinition.optString("version", null);
            final JSONObject qualifiers = testDefinition.optJSONObject("qualifiers");
            final String subpath = testDefinition.optString("subpath", null);

            if (invalid) {
                try {
                    PackageURL purl = new PackageURL(purlString);
                    fail("Inavlid purl should have caused an exception: " + purl);
                } catch (MalformedPackageURLException e) {
                    assertNotNull(e.getMessage());
                }
                continue;
            }

            PackageURL purl = new PackageURL(purlString);

            assertEquals("pkg", purl.getScheme());
            assertEquals(type, purl.getType());
            assertEquals(namespace, purl.getNamespace());
            assertEquals(name, purl.getName());
            assertEquals(version, purl.getVersion());
            assertEquals(subpath, purl.getSubpath());
            if (qualifiers == null) {
                assertNull(purl.getQualifiers());
            } else {
                assertNotNull(purl.getQualifiers());
                assertEquals(qualifiers.length(), purl.getQualifiers().size());
                qualifiers.keySet().forEach(key -> {
                    String value = qualifiers.getString(key);
                    assertTrue(purl.getQualifiers().containsKey(key));
                    assertEquals(value, purl.getQualifiers().get(key));
                });
            }
            assertEquals(cpurlString, purl.canonicalize());
        }
    }

    @Test
    void testConstructorParameters() throws MalformedPackageURLException {
        for (int i = 0; i < json.length(); i++) {
            JSONObject testDefinition = json.getJSONObject(i);

            final String purlString = testDefinition.getString("purl");
            final String cpurlString = testDefinition.optString("canonical_purl");
            final boolean invalid = testDefinition.getBoolean("is_invalid");

            System.out.println("Running test on: " + purlString);

            final String type = testDefinition.optString("type", null);
            final String namespace = testDefinition.optString("namespace", null);
            final String name = testDefinition.optString("name", null);
            final String version = testDefinition.optString("version", null);
            final JSONObject qualifiers = testDefinition.optJSONObject("qualifiers");
            final String subpath = testDefinition.optString("subpath", null);

            TreeMap<String, String> map = null;
            Map<String, String> hashMap = null;
            if (qualifiers != null) {
                map = qualifiers.toMap().entrySet().stream().collect(
                        TreeMap::new,
                        (qmap, entry) -> qmap.put(entry.getKey(), (String) entry.getValue()),
                        TreeMap::putAll
                );
                hashMap = new HashMap<>(map);
            }



            if (invalid) {
                try {
                    PackageURL purl = new PackageURL(type, namespace, name, version, map, subpath);
                    // If we get here, then only the scheme can be invalid
                    verifyComponentsEquals(purl, type, namespace, name, version, subpath, qualifiers);

                    if (!cpurlString.equals(purl.toString())) {
                        throw new MalformedPackageURLException("The PackageURL scheme is invalid for purl: " + purl);
                    }

                    fail("Invalid package url components should have caused an exception: " + purl);
                } catch (MalformedPackageURLException e) {
                    assertNotNull(e.getMessage());
                }
                continue;
            }

            PackageURL purl = new PackageURL(type, namespace, name, version, map, subpath);
            verifyComponentsEquals(purl, type, namespace, name, version, subpath, qualifiers);
            assertEquals(cpurlString, purl.canonicalize());
            if (qualifiers != null) {
                assertNotNull(purl.getQualifiers());
                assertEquals(qualifiers.length(), purl.getQualifiers().size());
                qualifiers.keySet().forEach(key -> {
                    String value = qualifiers.getString(key);
                    assertTrue(purl.getQualifiers().containsKey(key));
                    assertEquals(value, purl.getQualifiers().get(key));
                });
                PackageURL purl2 = new PackageURL(type, namespace, name, version, hashMap, subpath);
                assertEquals(purl.getQualifiers(), purl2.getQualifiers());
            }
        }
    }

    @Test
    void testConstructor() throws MalformedPackageURLException {
        PackageURL purl = new PackageURL("pkg:generic/namespace/name@1.0.0#");
        assertEquals("generic", purl.getType());
        assertNull(purl.getSubpath());

        purl = new PackageURL("pkg:generic/namespace/name@1.0.0?key=value==");
        assertEquals("generic", purl.getType());
        assertNotNull(purl.getQualifiers());
        assertEquals(1, purl.getQualifiers().size());
        assertTrue(purl.getQualifiers().containsValue("value=="));

        purl = new PackageURL("validtype", "name");
        assertNotNull(purl);

    }


    @Test
    void testConstructorWithEmptyType() {
        assertThrows(MalformedPackageURLException.class, () -> new PackageURL("", "name"));
    }

    @Test
    void testConstructorWithInvalidCharsType() {
        assertThrows(MalformedPackageURLException.class, () -> new PackageURL("invalid^type", "name"));
    }

    @Test
    void testConstructorWithInvalidNumberType() {
        assertThrows(MalformedPackageURLException.class, () -> new PackageURL("0invalid", "name"));
    }

    @Test
    void testConstructorWithInvalidSubpath() {
         assertThrows(MalformedPackageURLException.class, () -> new PackageURL("pkg:GOLANG/google.golang.org/genproto@abcdedf#invalid/%2F/subpath"));
    }


    @Test
    void testConstructorWithNullPurl() {
         assertThrows(MalformedPackageURLException.class, () -> new PackageURL(null));
    }

    @Test
    void testConstructorWithEmptyPurl() {
         assertThrows(MalformedPackageURLException.class, () -> new PackageURL(""));
    }

    @Test
    void testConstructorWithPortNumber() {
         assertThrows(MalformedPackageURLException.class, () -> new PackageURL("pkg://generic:8080/name"));
    }

    @Test
    void testConstructorWithUsername() {
         assertThrows(MalformedPackageURLException.class, () -> new PackageURL("pkg://user@generic/name"));
    }

    @Test
    void testConstructorWithInvalidUrl() {
         assertThrows(MalformedPackageURLException.class, () -> new PackageURL("invalid url"));
    }

    @Test
    void testConstructorWithDuplicateQualifiers() {
         assertThrows(MalformedPackageURLException.class, () -> new PackageURL("pkg://generic/name?key=one&key=two"));
    }

    @Test
    void testConstructorDuplicateQualifiersMixedCase() {
         assertThrows(MalformedPackageURLException.class, () -> new PackageURL("pkg://generic/name?key=one&KEY=two"));
    }

    @Test
    void testConstructorWithUppercaseKey() throws MalformedPackageURLException {
        PackageURL purl = new PackageURL("pkg://generic/name?KEY=one");
        assertNotNull(purl.getQualifiers());
        assertEquals("one", purl.getQualifiers().get("key"));
        PackageURL purl2 = new PackageURL("generic", null, "name", null, new TreeMap<String, String>() {{
            put("KEY", "one");
        }}, null);
        assertEquals(purl, purl2);
    }

    @Test
    void testConstructorWithEmptyKey() throws MalformedPackageURLException {
        PackageURL purl = new PackageURL("pkg://generic/name?KEY");
        assertNull(purl.getQualifiers());
        TreeMap<String, String> qualifiers = new TreeMap<>();
        qualifiers.put("KEY", null);
        PackageURL purl2 = new PackageURL("generic", null, "name", null, qualifiers, null);
        assertEquals(purl, purl2);
        qualifiers.put("KEY", "");
        PackageURL purl3 = new PackageURL("generic", null, "name", null, qualifiers, null);
        assertEquals(purl2, purl3);
    }

    private static void verifyComponentsEquals(PackageURL purl, String type, String namespace, String name, String version, String subpath, JSONObject qualifiers) {
        assertEquals("pkg", purl.getScheme());
        assertEquals(type, purl.getType());
        assertEquals(namespace, purl.getNamespace());
        assertEquals(name, purl.getName());
        assertEquals(version, purl.getVersion());
        assertEquals(subpath, purl.getSubpath());
        if (qualifiers != null) {
            assertNotNull(purl.getQualifiers());
            assertEquals(qualifiers.length(), purl.getQualifiers().size());
            qualifiers.keySet().forEach(key -> {
                String value = qualifiers.getString(key);
                assertTrue(purl.getQualifiers().containsKey(key));
                assertEquals(value, purl.getQualifiers().get(key));
            });
        }
    }

    @Test
    void testStandardTypes() {
        assertEquals("alpm", PackageURL.StandardTypes.ALPM);
        assertEquals("apk", PackageURL.StandardTypes.APK);
        assertEquals("bitbucket", PackageURL.StandardTypes.BITBUCKET);
        assertEquals("bitnami", PackageURL.StandardTypes.BITNAMI);
        assertEquals("cocoapods", PackageURL.StandardTypes.COCOAPODS);
        assertEquals("cargo", PackageURL.StandardTypes.CARGO);
        assertEquals("composer", PackageURL.StandardTypes.COMPOSER);
        assertEquals("conan", PackageURL.StandardTypes.CONAN);
        assertEquals("conda", PackageURL.StandardTypes.CONDA);
        assertEquals("cpan", PackageURL.StandardTypes.CPAN);
        assertEquals("cran", PackageURL.StandardTypes.CRAN);
        assertEquals("deb", PackageURL.StandardTypes.DEB);
        assertEquals("docker", PackageURL.StandardTypes.DOCKER);
        assertEquals("gem", PackageURL.StandardTypes.GEM);
        assertEquals("generic", PackageURL.StandardTypes.GENERIC);
        assertEquals("github", PackageURL.StandardTypes.GITHUB);
        assertEquals("golang", PackageURL.StandardTypes.GOLANG);
        assertEquals("hackage", PackageURL.StandardTypes.HACKAGE);
        assertEquals("hex", PackageURL.StandardTypes.HEX);
        assertEquals("huggingface", PackageURL.StandardTypes.HUGGINGFACE);
        assertEquals("luarocks", PackageURL.StandardTypes.LUAROCKS);
        assertEquals("maven", PackageURL.StandardTypes.MAVEN);
        assertEquals("mlflow", PackageURL.StandardTypes.MLFLOW);
        assertEquals("npm", PackageURL.StandardTypes.NPM);
        assertEquals("nuget", PackageURL.StandardTypes.NUGET);
        assertEquals("qpkg", PackageURL.StandardTypes.QPKG);
        assertEquals("oci", PackageURL.StandardTypes.OCI);
        assertEquals("pub", PackageURL.StandardTypes.PUB);
        assertEquals("pypi", PackageURL.StandardTypes.PYPI);
        assertEquals("rpm", PackageURL.StandardTypes.RPM);
        assertEquals("swid", PackageURL.StandardTypes.SWID);
        assertEquals("swift", PackageURL.StandardTypes.SWIFT);
    }

    @Test
    void testBaseEquals() throws Exception {
        PackageURL p1 = new PackageURL("pkg:generic/acme/example-component@1.0.0?key1=value1&key2=value2");
        PackageURL p2 = new PackageURL("pkg:generic/acme/example-component@1.0.0");
        assertTrue(p1.isBaseEquals(p2));
    }

    @Test
    void testCanonicalEquals() throws Exception {
        PackageURL p1 = new PackageURL("pkg:generic/acme/example-component@1.0.0?key1=value1&key2=value2");
        PackageURL p2 = new PackageURL("pkg:generic/acme/example-component@1.0.0?key2=value2&key1=value1");
        assertTrue(p1.isCanonicalEquals(p2));
    }

    @Test
    void testGetCoordinates() throws Exception {
        PackageURL purl = new PackageURL("pkg:generic/acme/example-component@1.0.0?key1=value1&key2=value2");
        assertEquals("pkg:generic/acme/example-component@1.0.0", purl.getCoordinates());
    }

    @Test
    void testGetCoordinatesNoCacheIssue89() throws Exception {
        PackageURL purl = new PackageURL("pkg:generic/acme/example-component@1.0.0?key1=value1&key2=value2");
        purl.canonicalize();
        assertEquals("pkg:generic/acme/example-component@1.0.0", purl.getCoordinates());
    }

    @Test
    void testNpmCaseSensitive() throws Exception {
        // e.g. https://www.npmjs.com/package/base64/v/1.0.0
        PackageURL base64Lowercase = new PackageURL("pkg:npm/base64@1.0.0");
        assertEquals("npm", base64Lowercase.getType());
        assertEquals("base64", base64Lowercase.getName());
        assertEquals("1.0.0", base64Lowercase.getVersion());

        // e.g. https://www.npmjs.com/package/Base64/v/1.0.0
        PackageURL base64Uppercase = new PackageURL("pkg:npm/Base64@1.0.0");
        assertEquals("npm", base64Uppercase.getType());
        assertEquals("Base64", base64Uppercase.getName());
        assertEquals("1.0.0", base64Uppercase.getVersion());
    }
}
