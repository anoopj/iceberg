/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.iceberg.variants;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import org.junit.jupiter.api.Test;

public class TestVariantBounds {

  @Test
  public void testComplexFieldBounds() {
    VariantMetadata metadata = Variants.metadata("$['location']['latitude']", "$['location']['longitude']", "$['user.name']");
    ShreddedObject bounds = Variants.object(metadata);
    bounds.put("$['location']['latitude']", Variants.of(37.7749));
    bounds.put("$['location']['longitude']", Variants.of(-122.4194));
    bounds.put("$['user.name']", Variants.of("John"));

    ByteBuffer serialized = serializeValue(metadata, bounds);
    byte[] serializedBytes = new byte[serialized.remaining()];
    serialized.get(serializedBytes);

    // Z85 encode the serialized bytes
    String z85Encoded = z85Encode(serializedBytes);
    System.out.println("Z85 Encoded: " + z85Encoded);

    // Z85 decode back to bytes
    byte[] z85Decoded = z85Decode(z85Encoded);
    // Deserialize back to VariantValue
    ByteBuffer decodedBuffer = ByteBuffer.wrap(z85Decoded).order(ByteOrder.LITTLE_ENDIAN);

    Variant deserialized = Variant.from(decodedBuffer); // validate deserialization
    VariantValue deserializedValue = deserialized.value();
    
    assertThat(deserializedValue).isEqualTo(bounds);
    
    VariantObject deserializedBounds = deserializedValue.asObject();
    assertThat(deserializedBounds.get("$['location']['latitude']")).isEqualTo(Variants.of(37.7749));
    assertThat(deserializedBounds.get("$['location']['longitude']")).isEqualTo(Variants.of(-122.4194));
    assertThat(deserializedBounds.get("$['user.name']")).isEqualTo(Variants.of("John"));
  }

  @Test
  public void testZ85EncodeDecodeRoundTrip() {
    byte[] testData = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    String encoded = z85Encode(testData);
    byte[] decoded = z85Decode(encoded);
    
    assertThat(decoded).isEqualTo(testData);
  }

  @Test
  public void testZ85EncodeKnownValues() {
    byte[] input = {(byte)0x86, 0x4F, (byte)0xD2, 0x6F, (byte)0xB5, 0x59, (byte)0xF7, 0x5B};
    String expected = "HelloWorld";
    String actual = z85Encode(input);
    
    assertThat(actual).isEqualTo(expected);
  }

  private ByteBuffer serializeValue(VariantMetadata metadata, VariantValue value) {
    ByteBuffer buffer =
            ByteBuffer.allocate(metadata.sizeInBytes() + value.sizeInBytes())
                    .order(ByteOrder.LITTLE_ENDIAN);
    metadata.writeTo(buffer, 0);
    value.writeTo(buffer, metadata.sizeInBytes());
    return buffer;
  }

  static String z85Encode(byte[] data) {
    String encoder = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#";
    StringBuilder encoded = new StringBuilder();
    
    int originalLength = data.length;
    int paddedLength = ((originalLength + 3) / 4) * 4; // Round up to nearest multiple of 4
    byte[] paddedData = new byte[paddedLength];
    System.arraycopy(data, 0, paddedData, 0, originalLength);
    // Remaining bytes are already zero-padded by default
    
    for (int i = 0; i < paddedData.length; i += 4) {
      long value = 0;
      for (int j = 0; j < 4; j++) {
        value = (value << 8) | (paddedData[i + j] & 0xFF);
      }
      
      char[] chars = new char[5];
      for (int j = 4; j >= 0; j--) {
        chars[j] = encoder.charAt((int)(value % 85));
        value /= 85;
      }
      encoded.append(chars);
    }
    
    // Add padding indicator: append the number of padding bytes as a suffix
    int paddingBytes = paddedLength - originalLength;
    if (paddingBytes > 0) {
      encoded.append('=').append(paddingBytes);
    }
    
    return encoded.toString();
  }

  static byte[] z85Decode(String encoded) {
    String decoder = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#";
    
    // Check for padding indicator
    int paddingBytes = 0;
    String dataToDecode = encoded;
    if (encoded.contains("=")) {
      int equalsIndex = encoded.lastIndexOf('=');
      if (equalsIndex < encoded.length() - 1) {
        try {
          paddingBytes = Integer.parseInt(encoded.substring(equalsIndex + 1));
          dataToDecode = encoded.substring(0, equalsIndex);
        } catch (NumberFormatException e) {
          throw new IllegalArgumentException("Invalid padding indicator in encoded string");
        }
      }
    }
    
    if (dataToDecode.length() % 5 != 0) {
      throw new IllegalArgumentException("Encoded string length must be divisible by 5");
    }
    
    byte[] decoded = new byte[(dataToDecode.length() / 5) * 4];
    
    for (int i = 0; i < dataToDecode.length(); i += 5) {
      long value = 0;
      for (int j = 0; j < 5; j++) {
        char c = dataToDecode.charAt(i + j);
        int index = decoder.indexOf(c);
        if (index == -1) {
          throw new IllegalArgumentException("Invalid character in encoded string: " + c);
        }
        value = value * 85 + index;
      }
      
      int outIndex = (i / 5) * 4;
      for (int j = 3; j >= 0; j--) {
        decoded[outIndex + j] = (byte)(value & 0xFF);
        value >>= 8;
      }
    }
    
    // Remove padding bytes
    if (paddingBytes > 0) {
      byte[] result = new byte[decoded.length - paddingBytes];
      System.arraycopy(decoded, 0, result, 0, result.length);
      return result;
    }
    
    return decoded;
  }
}