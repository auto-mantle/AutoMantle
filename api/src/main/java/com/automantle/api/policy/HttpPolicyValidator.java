package com.automantle.api.policy;

import com.automantle.api.config.HttpPolicyProperties;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import org.springframework.stereotype.Component;

@Component
public final class HttpPolicyValidator {
    private static final int MAX_DNS_HOST_LENGTH = 253;
    private final HttpPolicyProperties limits;

    public HttpPolicyValidator(HttpPolicyProperties limits) {
        this.limits = limits;
    }

    public String method(String input) {
        String method = requireText(input).toLowerCase(Locale.ROOT);
        if (!validMethod(method)) {
            throw new IllegalArgumentException("Invalid HTTP method");
        }
        return method;
    }

    public List<String> ruleMethods(List<String> input) {
        List<String> methods = values(input);
        if (!methods.stream().allMatch(HttpPolicyValidator::validMethod)) {
            throw new IllegalArgumentException("Rule methods must be lowercase HTTP tokens");
        }
        return methods;
    }

    public String host(String input) {
        requireText(input);
        String host = input.toLowerCase(Locale.ROOT);
        if (host.length() > MAX_DNS_HOST_LENGTH || host.matches("[0-9]+([.][0-9]+){3}")) {
            throw new IllegalArgumentException("Expected an exact DNS host name");
        }
        for (String label : host.split("[.]", -1)) {
            if (!label.matches("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")) {
                throw new IllegalArgumentException(
                        "Hosts must be exact DNS names without schemes, ports or wildcards");
            }
        }
        return host;
    }

    public List<String> hosts(List<String> input) {
        List<String> hosts = values(input).stream().map(this::host).toList();
        if (new HashSet<>(hosts).size() != hosts.size()) {
            throw new IllegalArgumentException("Duplicate hosts");
        }
        return hosts;
    }

    public String path(String input) {
        validatePath(requireText(input), false);
        return input;
    }

    public List<String> pathPatterns(List<String> input) {
        List<String> paths = values(input);
        paths.forEach(path -> validatePath(path, true));
        return paths;
    }

    public void validateListSize(List<?> input) {
        if (input == null || input.isEmpty() || input.size() > limits.maxRuleValues()) {
            throw new IllegalArgumentException(
                    "Expected between 1 and " + limits.maxRuleValues() + " values");
        }
    }

    private List<String> values(List<String> input) {
        validateListSize(input);
        input.forEach(HttpPolicyValidator::requireText);
        if (new HashSet<>(input).size() != input.size()) {
            throw new IllegalArgumentException("Duplicate values");
        }
        return List.copyOf(input);
    }

    private static String requireText(String value) {
        if (value == null || value.isEmpty()) {
            throw new IllegalArgumentException("Expected a nonempty string");
        }
        return value;
    }

    private static boolean validMethod(String method) {
        return method.matches("[a-z0-9!#$%&'*+.^_`|~\\-]+");
    }

    private void validatePath(String input, boolean pattern) {
        String path =
                pattern && input.endsWith("/*") ? input.substring(0, input.length() - 1) : input;
        if (path.length() > limits.maxPathLength()
                || !path.matches("/[A-Za-z0-9%/_~!$&'()+,;=:@.\\-]*")
                || path.contains("//")) {
            throw new IllegalArgumentException(
                    "Paths must be absolute ASCII paths; only a trailing /* wildcard is supported"
                            + " in rules");
        }
        if (path.contains("%")) {
            validateEncodedPath(path);
        }
        for (String segment : path.split("/", -1)) {
            if (segment.equals(".") || segment.equals("..")) {
                throw new IllegalArgumentException("Dot segments are not supported");
            }
        }
    }

    private static void validateEncodedPath(String path) {
        var decoded = new ByteArrayOutputStream();
        for (int i = 0; i < path.length(); i++) {
            char c = path.charAt(i);
            if (c != '%') {
                decoded.write(c);
                continue;
            }
            if (i + 2 >= path.length() || !path.substring(i + 1, i + 3).matches("[0-9A-F]{2}")) {
                throw new IllegalArgumentException("Invalid encoded path");
            }
            int b = Integer.parseInt(path.substring(i + 1, i + 3), 16);
            i += 2;
            if (b < 128) {
                throw new IllegalArgumentException("Noncanonical encoded path");
            }
            decoded.write(b);
        }
        try {
            StandardCharsets.UTF_8
                    .newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(decoded.toByteArray()));
        } catch (CharacterCodingException ignored) {
            throw new IllegalArgumentException("Invalid UTF-8 path");
        }
    }
}
