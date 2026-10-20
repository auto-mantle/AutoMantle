package com.automantle.api.entity;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

import java.util.Map;

@Converter
public class JsonMapConverter implements AttributeConverter<Map<String, Object>, String> {
    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final TypeReference<Map<String, Object>> TYPE = new TypeReference<>() {};

    @Override
    public String convertToDatabaseColumn(Map<String, Object> value) {
        return value == null ? null : JSON.writeValueAsString(value);
    }

    @Override
    public Map<String, Object> convertToEntityAttribute(String value) {
        return value == null ? null : JSON.readValue(value, TYPE);
    }
}
