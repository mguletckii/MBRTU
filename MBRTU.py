#sudo apt-get install libmysqlclient-dev
#sudo apt install python3-pip
#sudo pip3 install mysqlclient
#sudo pip3 install configobj


def programm_path():
    import sys
    return sys.argv[0][0: -(len(sys.argv[0].split('/')[-1]))]


def get_crc(data):
    crc_table = [0x0000, 0xC0C1, 0xC181, 0x0140, 0xC301, 0x03C0, 0x0280, 0xC241, 0xC601, 0x06C0, 0x0780, 0xC741, 0x0500,
                 0xC5C1, 0xC481, 0x0440, 0xCC01, 0x0CC0, 0x0D80, 0xCD41, 0x0F00, 0xCFC1, 0xCE81, 0x0E40, 0x0A00, 0xCAC1,
                 0xCB81, 0x0B40, 0xC901, 0x09C0, 0x0880, 0xC841, 0xD801, 0x18C0, 0x1980, 0xD941, 0x1B00, 0xDBC1, 0xDA81,
                 0x1A40, 0x1E00, 0xDEC1, 0xDF81, 0x1F40, 0xDD01, 0x1DC0, 0x1C80, 0xDC41, 0x1400, 0xD4C1, 0xD581, 0x1540,
                 0xD701, 0x17C0, 0x1680, 0xD641, 0xD201, 0x12C0, 0x1380, 0xD341, 0x1100, 0xD1C1, 0xD081, 0x1040, 0xF001,
                 0x30C0, 0x3180, 0xF141, 0x3300, 0xF3C1, 0xF281, 0x3240, 0x3600, 0xF6C1, 0xF781, 0x3740, 0xF501, 0x35C0,
                 0x3480, 0xF441, 0x3C00, 0xFCC1, 0xFD81, 0x3D40, 0xFF01, 0x3FC0, 0x3E80, 0xFE41, 0xFA01, 0x3AC0, 0x3B80,
                 0xFB41, 0x3900, 0xF9C1, 0xF881, 0x3840, 0x2800, 0xE8C1, 0xE981, 0x2940, 0xEB01, 0x2BC0, 0x2A80, 0xEA41,
                 0xEE01, 0x2EC0, 0x2F80, 0xEF41, 0x2D00, 0xEDC1, 0xEC81, 0x2C40, 0xE401, 0x24C0, 0x2580, 0xE541, 0x2700,
                 0xE7C1, 0xE681, 0x2640, 0x2200, 0xE2C1, 0xE381, 0x2340, 0xE101, 0x21C0, 0x2080, 0xE041, 0xA001, 0x60C0,
                 0x6180, 0xA141, 0x6300, 0xA3C1, 0xA281, 0x6240, 0x6600, 0xA6C1, 0xA781, 0x6740, 0xA501, 0x65C0, 0x6480,
                 0xA441, 0x6C00, 0xACC1, 0xAD81, 0x6D40, 0xAF01, 0x6FC0, 0x6E80, 0xAE41, 0xAA01, 0x6AC0, 0x6B80, 0xAB41,
                 0x6900, 0xA9C1, 0xA881, 0x6840, 0x7800, 0xB8C1, 0xB981, 0x7940, 0xBB01, 0x7BC0, 0x7A80, 0xBA41, 0xBE01,
                 0x7EC0, 0x7F80, 0xBF41, 0x7D00, 0xBDC1, 0xBC81, 0x7C40, 0xB401, 0x74C0, 0x7580, 0xB541, 0x7700, 0xB7C1,
                 0xB681, 0x7640, 0x7200, 0xB2C1, 0xB381, 0x7340, 0xB101, 0x71C0, 0x7080, 0xB041, 0x5000, 0x90C1, 0x9181,
                 0x5140, 0x9301, 0x53C0, 0x5280, 0x9241, 0x9601, 0x56C0, 0x5780, 0x9741, 0x5500, 0x95C1, 0x9481, 0x5440,
                 0x9C01, 0x5CC0, 0x5D80, 0x9D41, 0x5F00, 0x9FC1, 0x9E81, 0x5E40, 0x5A00, 0x9AC1, 0x9B81, 0x5B40, 0x9901,
                 0x59C0, 0x5880, 0x9841, 0x8801, 0x48C0, 0x4980, 0x8941, 0x4B00, 0x8BC1, 0x8A81, 0x4A40, 0x4E00, 0x8EC1,
                 0x8F81, 0x4F40, 0x8D01, 0x4DC0, 0x4C80, 0x8C41, 0x4400, 0x84C1, 0x8581, 0x4540, 0x8701, 0x47C0, 0x4680,
                 0x8641, 0x8201, 0x42C0, 0x4380, 0x8341, 0x4100, 0x81C1, 0x8081, 0x4040]

    crc_hi = 0xFF
    crc_lo = 0xFF

    for w in data:
        index = crc_lo ^ w
        crc_val = crc_table[index]
        crc_temp = int(crc_val / 256)
        crc_val_low = crc_val - (crc_temp * 256)
        crc_lo = crc_val_low ^ crc_hi
        crc_hi = crc_temp

    return bytes([crc_lo, crc_hi])


def add_crc(data):

    data.extend(get_crc(data))

    return data


def mb_get_package(addr, fun, offset, quantity):
    data = bytearray([addr, fun])

    for byte in offset.to_bytes(2, byteorder='big'):
        data.append(byte)
    for byte in quantity.to_bytes(2, byteorder='big'):
        data.append(byte)

    return add_crc(data)


def mb_check_error(config, device, data):
    error = {129, 130, 131, 132, 133, 134, 143, 144}
    error_code = {1: "Illegal Function", 2: "Illegal Data Address",
                  3: "Illegal Data Value", 4: "Slave Device Failure",
                  5: "Acknowledge", 6: "Slave Device Busy",
                  7: "Negative Acknowledge", 8: "Memory Parity Error",
                  10: "Gateway Path Unavailable", 11: "Gateway Target Device Failed to Respond"}
 
    crc = get_crc(data[0:-2])
    if crc == data[-2:]:
        if data[0] == int(device["address"]):
            if data[1] in error:
                try:
                    print('Modbus Error:', error_code[data[2]])
                except KeyError:
                    print('Modbus Package ERROR! Unknown error code: ', data[2])
            elif (data[1] == 1) and (int(int(device["quantity"])/9)+1 == (data[2])):
                return True
            elif int(device["quantity"]) == (data[2]/2):
                return True
            else:
                if data[1] == 1:
                    print('Wrong data!', config["host"], ':', config["port"], 'Addr:',
                          device["address"], 'Command quantity: ', (int(device["quantity"])/9)+1,
                          ' Package quantity: ', data[2])
                else:
                    print('Wrong data!', config["host"], ':', config["port"], 'Addr:',
                        device["address"], 'Command quantity: ', device["quantity"],
                        ' Package quantity: ', int(data[2]/2))
        else:
            print('Modbus Error! Different Slave Address! ')
    else:
        print('Modbus CRC Error!', config["host"], ':', config["port"], 'Addr:',
              device["address"], 'Received CRC: ', data[-2:], 'CRC: ', crc, 'Data: ', data)
    return False


def mb_pars_offsets(config):
    try:
        parsed_offsets = {}
        if config.get("db_extra_offset") is not None:
            for element in config["db_extra_offset"]:
                split_offset = element.split(":")
                if len(split_offset) > 1:
                   for i in range(int(split_offset[1])+1 - int(split_offset[0])):
                       if config["db_extra_offset"][element].isdigit():
                           parsed_offsets[int(split_offset[0]) + i] = \
                               int(config["db_extra_offset"][element]) + i
                       else:
                           parsed_offsets[int(split_offset[0]) + i] = \
                               config["db_extra_offset"][element]
                else:
                   parsed_offsets[int(split_offset[0])] = \
                       int(config["db_extra_offset"][element])

    except ValueError:
        print("Modbus Config ERROR! db_extra_offset", split_offset)
    return parsed_offsets


def mb_data_to_dict(config, data):
    data_dict = {}
    db_map = mb_pars_offsets(config)

    for i in range(0, int(config["quantity"])):
        offset = int(config.get("db_offset"))
        if offset is None:
            offset = int(config["offset"])
        if db_map.get(int(config["offset"])+i) is not None:
            db_element = db_map.get(int(config["offset"])+i)
        else:
            db_element = offset + i
        if db_element != "x":
            if data[1] == 3 or data[1] == 4:
                data_dict[db_element] = \
                    int.from_bytes(data[(i*2)+3:(i*2)+5], byteorder='big')
            if data[1] == 1:
                data_dict[db_element] = ((data[3+i//8]) >> (i-8*(i//8))) & 1

    return data_dict


def mb_get_data(config):
    import socket
    import time

    sock = socket.socket()
    sock.settimeout(int(config["timeout"]) / 1000)

    try:
        sock.connect((config["host"], int(config["port"])))
        data_list = {}

        for device_name in config["Devices"]:
            device = config["Devices"][device_name]
            for trying in range(int(config["try"])):
                try:
                    sock.send(mb_get_package(int(device["address"]), int(device["function"]),
                                             int(device["offset"]), int(device["quantity"])))
                    data_tx = sock.recv(int(device["quantity"]) * 2 + 5)
                    if mb_check_error(config, device, data_tx):
                        print("Done", device)
                        data_list.update(mb_data_to_dict(device, data_tx))

                        break
                    print("Try again", device)

                except socket.timeout:
                    print('Modbus Timeout. Time: ', config["timeout"], ' msec!', config["host"],
                          ':', config["port"], 'Addr:', device["address"], '/',
                          device["offset"], '/', device["quantity"])
                except KeyError:
                    print("Modbus Config ERROR!", config["host"], ":", config["port"])
                    break

                print("Delay between polls: ", float(config["delay"]), "ms")
                time.sleep(float(config["delay"]) / 1000)

        sock.close()

        return data_list

    except socket.error:
        print('Modbus TCP Connection Refused!', config["host"], ':', config["port"])
        return []


def msql_connect(config):
    import MySQLdb
    import sys
    try:
        conn = MySQLdb.connect(host=config["host"], user=config["login"],
                               passwd=config["password"], db=config["db"])
    except MySQLdb.Error as err:
        print("Connection error: {}".format(err))
        sys.exit(1)

    return conn


def msql_ins_dup_str(config):
    config = {"db": config["db"], "table": config["table"], "identifier": config["id"],
              "value": config["value"], "update": config["update"], "id_value": "%s"}
    sql = "INSERT INTO %(db)s.%(table)s (`%(identifier)s`, `%(value)s`, `%(update)s`) " \
          "VALUES (%(id_value)s, '%(id_value)s', NULL) " \
          "ON DUPLICATE KEY UPDATE `%(value)s` = VALUES (`%(value)s`), `%(update)s`=NULL;"
    return sql % config


def msql_set_data(config, data):
    if data is None:
        print("Data is None")
    else:
        import MySQLdb
        sql = msql_ins_dup_str(config)
        conn = msql_connect(config)
        for i in data:
            try:
                cur = conn.cursor()
                cur.execute(sql, (i, data[i]))
            except MySQLdb.Error as err:
                print("Query error: {}".format(err))

        conn.autocommit(on=True)
        conn.close()


def send_query(cfg):
    msql_set_data(msql_cfg, mb_get_data(cfg))


from configobj import ConfigObj

msql_cfg = ConfigObj(programm_path() + "db_config.cfg")["MySQL"]

mb_cfg = ConfigObj(programm_path() + "mb_config.cfg")


import threading
threadlist = []

for cfg in mb_cfg:
    newthread = threading.Thread(target=send_query, args=(mb_cfg[cfg],))
    newthread.daemon = True
    threadlist.append(newthread)
    newthread.start()

for threat in threadlist:
    threat.join()
