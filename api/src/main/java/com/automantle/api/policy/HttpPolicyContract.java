package com.automantle.api.policy;

import com.automantle.api.config.HttpPolicyProperties;
import org.springframework.http.InvalidMediaTypeException;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;

import tools.jackson.core.StreamReadFeature;
import tools.jackson.core.JacksonException;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.json.JsonMapper;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

@Component
public final class HttpPolicyContract {

    private static final JsonMapper PREVIEW_MAPPER =
            JsonMapper.builder()
                    .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
                    .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                    .build();

    private final HttpPolicyProperties limits;
    private final HttpPolicyValidator validator;

    public HttpPolicyContract(HttpPolicyProperties limits, HttpPolicyValidator validator) {
        this.limits = limits;
        this.validator = validator;
    }

    public HttpAction action(Map<String, Object> value) {
        String invalidAction =
                "Expected an HTTP action with method, host, path and optional body/credential"
                        + " review metadata";
        MetadataFields fields = MetadataFields.from(value, invalidAction);
        if (!"http".equals(fields.take("resource_type"))) {
            throw new IllegalArgumentException(invalidAction);
        }
        String method = validator.method(fields.text("method"));
        String host = validator.host(fields.text("host"));
        String path = validator.path(fields.text("path"));
        HttpBody body = fields.has("body") ? body(fields.take("body")) : null;
        List<HttpCredential> credentials =
                fields.has("credentials")
                        ? credentials(fields.take("credentials"))
                        : List.of();
        String requestSha256 =
                fields.has("request_sha256") ? fields.text("request_sha256") : null;
        if (requestSha256 != null && !HttpBody.validSha256(requestSha256)) {
            throw new IllegalArgumentException("Invalid request fingerprint");
        }
        fields.rejectUnexpected("Unexpected HTTP action fields");
        return new HttpAction(method, host, path, body, credentials, requestSha256);
    }

    public List<HttpCredential> credentials(Object input) {
        if (!(input instanceof List<?> values)
                || values.isEmpty()
                || values.size() > limits.maxCredentialPlacements()) {
            throw new IllegalArgumentException(
                    "Expected 1-" + limits.maxCredentialPlacements() + " credential placements");
        }
        List<HttpCredential> result = new ArrayList<>();
        Set<String> locations = new HashSet<>();
        for (Object item : values) {
            HttpCredential credential = credential(item);
            if (!locations.add(credential.location() + ":" + credential.selector())) {
                throw new IllegalArgumentException("Invalid or duplicate credential placement");
            }
            result.add(credential);
        }
        return List.copyOf(result);
    }

    private HttpCredential credential(Object input) {
        MetadataFields fields = MetadataFields.from(input, "Invalid credential placement");
        String placeholder = fields.text("placeholder");
        HttpCredential credential;
        if (fields.has("header")) {
            String header = fields.text("header");
            fields.rejectUnexpected("Invalid credential header");
            if (!("authorization".equals(header) || "x-api-key".equals(header))) {
                throw new IllegalArgumentException("Invalid credential header");
            }
            credential = new HttpCredential(placeholder, header);
        } else {
            String location = fields.text("location");
            String selector = fields.text("selector");
            fields.rejectUnexpected("Unexpected credential fields");
            credential = new HttpCredential(placeholder, location, selector);
        }
        if (!HttpCredential.validName(placeholder) || !validPlacement(credential)) {
            throw new IllegalArgumentException("Invalid credential placement");
        }
        return credential;
    }

    private static boolean supportsJsonPreview(String contentType) {
        if (contentType.indexOf(';') != contentType.lastIndexOf(';')) {
            return false;
        }
        try {
            MediaType type = MediaType.parseMediaType(contentType);
            String media = type.getType() + "/" + type.getSubtype();
            boolean supported = switch (media) {
                case "application/json", "application/merge-patch+json", "application/json-patch+json" -> true;
                default -> false;
            };
            return supported
                    && (type.getParameters().isEmpty()
                            || (type.getParameters().size() == 1
                                    && StandardCharsets.UTF_8.equals(type.getCharset())));
        } catch (InvalidMediaTypeException error) {
            return false;
        }
    }

    private static boolean reservedHeader(String header) {
        return switch (header) {
            case "host", "content-length", "content-type", "content-encoding",
                    "transfer-encoding", "connection", "proxy-connection",
                    "proxy-authorization", "upgrade", "expect", "te", "trailer",
                    "accept-encoding" -> true;
            default -> false;
        };
    }

    private boolean validPlacement(HttpCredential credential) {
        String selector = credential.selector();
        return switch (credential.location()) {
            case "header" ->
                    selector.length() <= limits.maxSelectorLength()
                            && selector.matches("[a-z0-9][a-z0-9-]*")
                            && !reservedHeader(selector);
            case "json" ->
                    selector.length() <= limits.maxJsonPointerLength()
                            && selector.startsWith("/")
                            && selector.matches("(?:[^~\\p{Cntrl}]|~[01])+");
            case "query" ->
                    selector.length() <= limits.maxSelectorLength()
                            && selector.matches("[A-Za-z0-9_.-]+");
            default -> false;
        };
    }

    private HttpBodyPreview preview(Object input) {
        MetadataFields fields = MetadataFields.from(input, "Invalid JSON preview");
        if (fields.has("omitted")) {
            if (!Boolean.TRUE.equals(fields.take("omitted"))) {
                throw new IllegalArgumentException("Invalid JSON preview");
            }
            fields.rejectUnexpected("Invalid JSON preview");
            return new HttpBodyPreview(null, false, true);
        }
        Object jsonValue = fields.take("json");
        Object redactedValue = fields.take("redacted");
        fields.rejectUnexpected("Invalid JSON preview");
        if (!(jsonValue instanceof String json)
                || !(redactedValue instanceof Boolean redacted)
                || json.getBytes(StandardCharsets.UTF_8).length
                        > limits.maxPreviewSize().toBytes()) {
            throw new IllegalArgumentException(
                    "JSON preview requires bounded JSON text and a redaction flag");
        }
        try {
            var node = PREVIEW_MAPPER.readTree(json);
            if (node == null || node.isMissingNode()) {
                throw new IllegalArgumentException("Invalid JSON preview text");
            }
        } catch (JacksonException error) {
            throw new IllegalArgumentException("Invalid JSON preview text");
        }
        return new HttpBodyPreview(json, redacted, false);
    }

    private HttpBody body(Object input) {
        MetadataFields fields = MetadataFields.from(
                input, "Body requires a fingerprint and optional sanitized preview");
        Object contentType = fields.take("content_type");
        Object byteSize = fields.take("size_bytes");
        if (!(contentType instanceof String type)
                || !(byteSize instanceof Integer || byteSize instanceof Long)) {
            throw new IllegalArgumentException(
                    "Body requires a content type and integer byte size");
        }
        long size = ((Number) byteSize).longValue();
        String digest = fields.text("sha256");
        if (size < 0 || size > limits.maxBodySize().toBytes() || !HttpBody.validSha256(digest)) {
            throw new IllegalArgumentException("Invalid body size or SHA-256");
        }
        if (!validContentType(type) || !HttpBody.matchesEmptyFingerprint(size, digest)) {
            throw new IllegalArgumentException("Unsupported body fingerprint");
        }
        HttpBodyPreview preview = fields.has("preview") ? preview(fields.take("preview")) : null;
        fields.rejectUnexpected("Unexpected body fields");
        if (size == 0 && preview != null) {
            throw new IllegalArgumentException("Empty bodies do not have previews");
        }
        if (preview != null && !preview.omitted() && !supportsJsonPreview(type)) {
            throw new IllegalArgumentException("Opaque body previews must be omitted");
        }
        return new HttpBody(type, (int) size, digest, preview);
    }

    private boolean validContentType(String type) {
        return type.isEmpty()
                || (type.length() <= limits.maxContentTypeLength()
                        && type.matches(
                                "[A-Za-z0-9!#$%&'*+.^_`|~\\-]+/[A-Za-z0-9!#$%&'*+.^_`|~\\-]+(?:;["
                                        + " -~]*)?"));
    }

    public HttpRuleMatch match(Map<String, Object> value) {
        String invalidRule =
                "HTTP rules require resource_type, action, hosts, resource and optional"
                        + " credentials";
        MetadataFields fields = MetadataFields.from(value, invalidRule);
        if (!"http".equals(fields.take("resource_type"))) {
            throw new IllegalArgumentException(invalidRule);
        }
        List<String> methods = validator.ruleMethods(strings(fields.take("action")));
        List<String> hosts = validator.hosts(strings(fields.take("hosts")));
        List<String> paths = validator.pathPatterns(strings(fields.take("resource")));
        List<HttpCredential> credentials =
                fields.has("credentials")
                        ? credentials(fields.take("credentials"))
                        : List.of();
        fields.rejectUnexpected("Unexpected HTTP rule fields");
        if (credentials.stream()
                .anyMatch(c -> HttpCredential.isVmBearer(c.placeholder()))) {
            throw new IllegalArgumentException(
                    "VM login fingerprints cannot be configured as host credentials");
        }
        return new HttpRuleMatch(methods, hosts, paths, credentials);
    }

    private static String string(Object value) {
        if (!(value instanceof String text) || text.isEmpty()) {
            throw new IllegalArgumentException("Expected a nonempty string");
        }
        return text;
    }

    private List<String> strings(Object value) {
        if (!(value instanceof List<?> list)) {
            throw new IllegalArgumentException(
                    "Expected between 1 and " + limits.maxRuleValues() + " values");
        }
        validator.validateListSize(list);
        return list.stream().map(HttpPolicyContract::string).toList();
    }
}
