# print(packet['r-goose'].field_names)
import pandas as pd
import pyshark
# GOOSE_dst = 'b4:96:91:1f:03:de'
GOOSE_dst = '01:0c:cd:01:00:01'
GOOSE_sqnum = []


class in_goose:
    def __init__(self, packet):
        self.packet = packet


class out_rgoose:
    def __init__(self, packet):
        self.packet = packet


def goose_rgoose_table(file_path):
    """Функция формирует df из двух столбцов:
       в первом столбце сохраняется исходный goose,
       во втором - сформированный r-goose."""
    try:
        # Чтение .pcap файла
        k = 0  # для проверки что печать названий полей -однократно
        cap = pyshark.FileCapture(file_path)
        gs1_df = pd.DataFrame(columns=['goose_in', 'rgoose_out'])
        for packet in cap:
            layers = ([item.layer_name for item in packet.layers])
            # print(layers)
            if ("goose") in layers:
                if packet['ETH'].dst == GOOSE_dst:
                    # print(packet['ip'].field_names)
                    # удаляем дубликаты пакетов (если были)
                    if not packet['goose'].sqnum in gs1_df.index:
                        gs1 = in_goose(packet)
                        gs1_df.loc[gs1.packet['goose'].sqnum] = [gs1, ""]
            # ищем соответствующий r-goose
            if ("r-goose") in layers:
                if k == 0:
                    print(packet['r-goose'].field_names)
                    k += 1
                if (packet['r-goose'].goose_sqnum in gs1_df.index):
                    if (packet['r-goose'].goose_datset == gs1_df.loc[
                        packet['r-goose'].goose_sqnum, 'goose_in'].packet[
                            'goose'].datset):
                        rgs1 = out_rgoose(packet)
                        gs1_df.loc[
                            packet['r-goose'].goose_sqnum, 'rgoose_out'] = rgs1
        return gs1_df
    except Exception as e:
        print(f"Error reading pcap file: {e}")


def transition_time(df):
    """Возвращает df с дополнительным столбцом
       в который извлекается время изменения DS goose"""
    df['goose_time'] = df['goose_in'].apply(lambda x: x.packet['goose'].t)
    return df


def sniff_time(df):
    """Возвращает df с дополнительным столбцом
       в который извлекается время получения пакета интерфейсом"""
    df['goose_sniff'] = df['goose_in'].apply(lambda x:
                                             x.packet.sniff_timestamp)
    return df


def sniff_time_r(df):
    """Возвращает df с дополнительным столбцом
       в который извлекается время получения пакета интерфейсом
       для r-goose"""
    df['rgoose_sniff'] = df['rgoose_out'].apply(
        lambda x: x.packet.sniff_timestamp)
    return df


# Пример использования функции
pcap_file_path = "inp/RGOOSE4.pcapng"
out = goose_rgoose_table(pcap_file_path)
print(out)
out1 = transition_time(out)
print(out1)
out2 = sniff_time(out1)
print(out2[['goose_time', 'goose_sniff']])

out3 = sniff_time_r(out2)

df1 = (out3[['goose_sniff', 'rgoose_sniff']])
df1['Разность'] = pd.to_numeric(df1['rgoose_sniff']) -\
    pd.to_numeric(df1['goose_sniff'])
print(df1)
