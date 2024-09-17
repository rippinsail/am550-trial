#include "am550.h"

namespace esphome {
    namespace am550 {
        void AM550::dump_config() {
            ESP_LOGCONFIG(TAG, "AM550 Smartmeter:");
            ESP_LOGCONFIG(TAG, "  version: %s", AM550_VERSION);
        }
        
        void AM550::loop() {
            unsigned long currentTime = millis();

            while(available()) {
                uint8_t c = read();
                this->receiveBuffer.push_back(c);

                this->lastRead = currentTime;
            }
            
            if(!this->receiveBuffer.empty() && currentTime - this->lastRead > this->readTimeout){
                ESP_LOGV(TAG, "raw recieved data: %s", format_hex_pretty(this->receiveBuffer).c_str());
                
                 handle_message(this->receiveBuffer);
                // use static string for debugging:
                std::string hexInput = "7EA067CF022313FBF1E6E700DB0849534B687536864B4F20027E187993D225CDA195A03AFAC7567FE724D8CD4C7DC9180B679B1BAD7AF68520C68932CAC7817A6A5CB3FAFCC0CF07631F657A9105F35626C197A6CEAD17C6967866EC1434044D66EF056BE33DF1727E";  // Replace with actual hex string
                std::vector<uint8_t> staticBytes = hexToBytes(hexInput);
                //ESP_LOGV(TAG, "static data: %s", format_hex_pretty(std::vector<uint8_t>(staticBytes, staticBytes+10)));

                this->receiveBuffer.clear(); // Reset buffer
            }
        }

        // Function to convert hexadecimal string to byte array
        std::vector<uint8_t> AM550::hexToBytes(const std::string &hex) {
            std::vector<uint8_t> bytes;
            for (size_t i = 0; i < hex.length(); i += 2) {
                std::string byteString = hex.substr(i, 2);
                uint8_t byte = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
                bytes.push_back(byte);
            }
            return bytes;
        }

        int AM550::bytes_to_int(uint8_t bytes[], int left, int len) {
            int result = 0;
            for (unsigned int i = left; i < left+len; i++) {
                result = result * 256 + bytes[i];
            }
            return result;
        }

        void AM550::handle_message(std::vector<uint8_t> msg) {
            uint8_t datalen = msg.size();

            if(msg[0] != 0x7e || msg[1] != 0xA0) {
                ESP_LOGW(TAG, "wrong opening bytes: %02x %02x, expected 7e a0", msg[0], msg[1]);
                return;
            }

            if(datalen != msg[2]+2) {
                ESP_LOGW(TAG, "wrong msg length: %i, expected %i", datalen, msg[2]+2);
                return;
            }

            if(msg[datalen-1] != 0x7e) {
                ESP_LOGW(TAG, "wrong closing byte: %02x, expected 7e", msg[124]);
                return;
            }

            // Print the actual content starting at msg[16]
            char actual_content[6] = {0};  // Buffer for the 5 bytes + null terminator
            memcpy(actual_content, &msg[14], 5);
            ESP_LOGW(TAG, "Actual content at msg[16]: %s", actual_content);

            if(memcmp(&msg[14], "ISKhu", 5)!=0){
                ESP_LOGW(TAG, "Unknown smartmeter model, support is untested.");
            }

            // CRC Check
            int crc = this->CRC16.x25(msg.data() + 1, datalen-4);
            int expected_crc = msg[datalen-2] * 256 + msg[datalen-3];
            if(crc != expected_crc) {
                ESP_LOGW(TAG, "crc mismatch: calculated %04x, expected %04x", crc, expected_crc);
                return;
            }

            /*            
            ESP_LOGV(TAG, "start decrypting using key:");
            for (int i = 0; i < 16; ++i) {
                ESP_LOGV(TAG, "%02X.", this->key[i]);  // Print each byte in uppercase hexadecimal with a dot separator
            }
            */

            // Decrypt old
            uint8_t msglen = datalen - 33;
            uint8_t message[msglen] = {0};
            memcpy(message, msg.data() + 30, msglen);
            uint8_t nonce[16] = {0};
            memcpy(nonce, msg.data() + 16, 8);
            memcpy(nonce + 8, msg.data() + 26, 4);
            nonce[15] = 0x02;
            this->ctraes128.setKey(this->key, 16);
            this->ctraes128.setIV(nonce, 16);
            ESP_LOGV(TAG, "encrypted data: %s", format_hex_pretty(std::vector<uint8_t>(message, message+msglen)).c_str());            
            this->ctraes128.decrypt(message, message, msglen);
            ESP_LOGV(TAG, "nonce: %s", format_hex_pretty(std::vector<uint8_t>(nonce, nonce+msglen)).c_str());
            ESP_LOGV(TAG, "decrypted data: %s", format_hex_pretty(std::vector<uint8_t>(message, message+msglen)).c_str());

            // Decrypt new
            // std::vector<uint8_t> encryptedData(input.begin() + 28 + add, input.end() - 3);



            // Debug
            ESP_LOGV(TAG, "Checking decrypted message byte 0: %02x", message[0]);
            ESP_LOGV(TAG, "Checking decrypted message byte msglen-5: %02x", message[msglen-5]);
            ESP_LOGV(TAG, "Checking decrypted message byte msglen-10: %02x", message[msglen-5*2]);
            ESP_LOGV(TAG, "Checking decrypted message byte msglen-15: %02x", message[msglen-5*3]);
            ESP_LOGV(TAG, "Checking decrypted message byte msglen-20: %02x", message[msglen-5*4]);
            ESP_LOGV(TAG, "Checking decrypted message byte msglen-25: %02x", message[msglen-5*5]);
            ESP_LOGV(TAG, "Checking decrypted message byte msglen-30: %02x", message[msglen-5*6]);
            ESP_LOGV(TAG, "Checking decrypted message byte msglen-35: %02x", message[msglen-5*7]);
            ESP_LOGV(TAG, "Checking decrypted message byte msglen-40: %02x", message[msglen-5*8]);
            
            if(message[0] != 0x0f || message[msglen-5] != 0x06 || message[msglen-5*2] != 0x06
                || message[msglen-5*3] != 0x06 || message[msglen-5*4] != 0x06
                || message[msglen-5*5] != 0x06 || message[msglen-5*6] != 0x06
                || message[msglen-5*7] != 0x06 || message[msglen-5*8] != 0x06){
                ESP_LOGW(TAG, "decryption error, please check if your key is correct");
                return;
            }
            

            uint32_t active_energy_pos_raw    = bytes_to_int(message, msglen-4-5*7, 4);
            uint32_t active_energy_neg_raw    = bytes_to_int(message, msglen-4-5*6, 4);
            uint32_t reactive_energy_pos_raw  = bytes_to_int(message, msglen-4-5*5, 4);
            uint32_t reactive_energy_neg_raw  = bytes_to_int(message, msglen-4-5*4, 4);

            // use modulo 1000kwh for the energy sensors, because esphome sensors are only 32bit floats
            // values larger than that would suffer from precision errors
            // because the sensors are defined as total_increasing, home assistant will still correctly display consumption
            float active_energy_pos    = (active_energy_pos_raw%1000000)/1000.0;
            float active_energy_neg    = (active_energy_neg_raw%1000000)/1000.0;
            float reactive_energy_pos  = (reactive_energy_pos_raw%1000000)/1000.0;
            float reactive_energy_neg  = (reactive_energy_neg_raw%1000000)/1000.0;
            float active_power_pos     = bytes_to_int(message, msglen-4-5*3, 4);
            float active_power_neg     = bytes_to_int(message, msglen-4-5*2, 4);
            float reactive_power_pos   = bytes_to_int(message, msglen-4-5*1, 4);
            float reactive_power_neg   = bytes_to_int(message, msglen-4-5*0, 4);

            if(this->active_energy_pos != nullptr && this->active_energy_pos->state != active_energy_pos)
                this->active_energy_pos->publish_state(active_energy_pos);
            if(this->active_energy_neg != nullptr && this->active_energy_neg->state != active_energy_neg)
                this->active_energy_neg->publish_state(active_energy_neg);
            if(this->reactive_energy_pos != nullptr && this->reactive_energy_pos->state != reactive_energy_pos)
                this->reactive_energy_pos->publish_state(reactive_energy_pos);
            if(this->reactive_energy_neg != nullptr && this->reactive_energy_neg->state != reactive_energy_neg)
                this->reactive_energy_neg->publish_state(reactive_energy_neg);
            if(this->active_power_pos != nullptr && this->active_power_pos->state != active_power_pos)
                this->active_power_pos->publish_state(active_power_pos);
            if(this->active_power_neg != nullptr && this->active_power_neg->state != active_power_neg)
                this->active_power_neg->publish_state(active_power_neg);
            if(this->reactive_power_pos != nullptr && this->reactive_power_pos->state != reactive_power_pos)
                this->reactive_power_pos->publish_state(reactive_power_pos);
            if(this->reactive_power_neg != nullptr && this->reactive_power_neg->state != reactive_power_neg)
                this->reactive_power_neg->publish_state(reactive_power_neg);
            
            char buffer[16];
            if(this->active_energy_pos_raw != nullptr) {
                itoa(active_energy_pos_raw, buffer, 10);
                if(this->active_energy_pos_raw->state != buffer)
                    this->active_energy_pos_raw->publish_state(buffer);
            }
            if(this->active_energy_neg_raw != nullptr) {
                itoa(active_energy_neg_raw, buffer, 10);
                if(this->active_energy_neg_raw->state != buffer)
                    this->active_energy_neg_raw->publish_state(buffer);
            }
            if(this->reactive_energy_pos_raw != nullptr) {
                itoa(reactive_energy_pos_raw, buffer, 10);
                if(this->reactive_energy_pos_raw->state != buffer)
                    this->reactive_energy_pos_raw->publish_state(buffer);
            }
            if(this->reactive_energy_neg_raw != nullptr) {
                itoa(reactive_energy_neg_raw, buffer, 10);
                if(this->reactive_energy_neg_raw->state != buffer)
                    this->reactive_energy_neg_raw->publish_state(buffer);
            }
        }
    }
}