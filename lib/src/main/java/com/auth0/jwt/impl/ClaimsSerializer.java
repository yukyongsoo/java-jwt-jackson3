package com.auth0.jwt.impl;


import tools.jackson.core.JsonGenerator;
import tools.jackson.databind.SerializationContext;
import tools.jackson.databind.ser.std.StdSerializer;

import java.io.IOException;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Custom serializer used to write the resulting JWT.
 *
 * @param <T> the type this serializer operates on.
 */
public class ClaimsSerializer<T extends ClaimsHolder> extends StdSerializer<T> {

    public ClaimsSerializer(Class<T> t) {
        super(t);
    }

    @Override
    public void serialize(T holder, JsonGenerator gen, SerializationContext provider) {
        gen.writeStartObject();
        for (Map.Entry<String, Object> entry : holder.getClaims().entrySet()) {
            try {
                writeClaim(entry, gen, provider);
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
        gen.writeEndObject();
    }

    /**
     * Writes the given entry to the JSON representation. Custom claim serialization handling can override this method
     * to provide use-case specific serialization. Implementors who override this method must write
     * the field name and the field value.
     *
     * @param entry The entry that corresponds to the JSON field to write
     * @param gen The {@code JsonGenerator} to use
     * @param provider The {@code SerializationContext} to use
     * @throws IOException if there is either an underlying I/O problem or encoding issue at format layer
     */
    protected void writeClaim(Map.Entry<String, Object> entry,
                              JsonGenerator gen,
                              SerializationContext provider) throws IOException {
        gen.writeName(entry.getKey());
        handleSerialization(entry.getValue(), gen, provider);
    }

    private static void handleSerialization(Object value,
                                            JsonGenerator gen,
                                            SerializationContext provider) throws IOException {
        if (value instanceof Date) {
            gen.writeNumber(dateToSeconds((Date) value));
        } else if (value instanceof Instant) { // EXPIRES_AT, ISSUED_AT, NOT_BEFORE, custom Instant claims
            gen.writeNumber(instantToSeconds((Instant) value));
        } else if (value instanceof Map) {
            serializeMap((Map<?, ?>) value, gen, provider);
        } else if (value instanceof List) {
            serializeList((List<?>) value, gen, provider);
        } else {
            gen.writePOJO(value);
        }
    }

    private static void serializeMap(Map<?, ?> map,
                                     JsonGenerator gen,
                                     SerializationContext provider) throws IOException {
        gen.writeStartObject();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            gen.writeName((String) entry.getKey());
            Object value = entry.getValue();
            handleSerialization(value, gen, provider);
        }
        gen.writeEndObject();
    }

    private static void serializeList(List<?> list,
                                      JsonGenerator gen,
                                      SerializationContext provider) throws IOException {
        gen.writeStartArray();
        for (Object entry : list) {
            handleSerialization(entry, gen, provider);
        }
        gen.writeEndArray();
    }

    private static long instantToSeconds(Instant instant) {
        return instant.getEpochSecond();
    }

    private static long dateToSeconds(Date date) {
        return date.getTime() / 1000;
    }
}
