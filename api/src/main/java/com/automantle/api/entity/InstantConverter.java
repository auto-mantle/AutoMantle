package com.automantle.api.entity;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;

@Converter(autoApply = true)
public class InstantConverter implements AttributeConverter<Instant, String> {
    private static final DateTimeFormatter FORMAT =
            new DateTimeFormatterBuilder().appendInstant(9).toFormatter();

    @Override
    public String convertToDatabaseColumn(Instant value) {
        return value == null ? null : FORMAT.format(value);
    }

    @Override
    public Instant convertToEntityAttribute(String value) {
        return value == null ? null : Instant.parse(value);
    }
}
