import esphome.codegen as cg
import esphome.config_validation as cv
from esphome.const import *
from esphome.components import uart

DEPENDENCIES = ["uart"]
CODEOWNERS = ["@bernikr", "@rippinsail"]
AUTO_LOAD = ["text_sensor", "sensor"]
MULTI_CONF = True

CONF_AM550_ID = "am550_id"
CONG_AM550_KEY = "key"

pipsolar_ns = cg.esphome_ns.namespace("am550")
am550Component = pipsolar_ns.class_("AM550", cg.Component)

AM550_COMPONENT_SCHEMA = cv.Schema(
    {
        cv.GenerateID(CONF_AM550_ID): cv.use_id(am550Component),
    }
)

def validate_key(value):
    value = cv.string(value).replace(" ", "").upper()
    if len(value) != 32 or any(c not in "0123456789ABCDEF" for c in value):
        raise cv.Invalid(
            "Key must be 16 bytes in Hex"
        )
    value = [int(value[i*2:i*2+2], 16) for i in range(16)]
    return value

CONFIG_SCHEMA = cv.All(
    cv.Schema({
        cv.GenerateID(): cv.declare_id(am550Component),
        cv.Required(CONG_AM550_KEY): validate_key,
        cv.GenerateID(CONF_RAW_DATA_ID): cv.declare_id(cg.uint8),
        })
    .extend(uart.UART_DEVICE_SCHEMA)
)

def to_code(config):
    var = cg.new_Pvariable(config[CONF_ID])
    arr = cg.progmem_array(config[CONF_RAW_DATA_ID], config[CONG_AM550_KEY])
    cg.add(var.set_key(arr))
    yield cg.register_component(var, config)
    yield uart.register_uart_device(var, config)
    cg.add_library("frankboesing/FastCRC", "1.41")
    cg.add_library("rweather/Crypto", "0.4.0")