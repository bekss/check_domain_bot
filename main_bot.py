import whois
import telebot
import socket


from OpenSSL.SSL import Connection, Context, SSLv3_METHOD, TLSv1_2_METHOD
from datetime import datetime


domain_bot = telebot.TeleBot('102sj4919x351qasx4ljfasj23ljasf32sldf2')
keyboard1 = telebot.types.ReplyKeyboardMarkup(True, True)
keyboard1.row('/help','/start')


@domain_bot.message_handler(commands=['start'])
def start_message(message):
    domain_bot.send_message(message.chat.id, 'Hello. Here you can find information about any domain and the bot is still a test.'
                                             'Please write a '
                                             'domain to view information about this domain. \nFor example: google.com,'
                                             'youtube.com \n' 'But it does not work for google.com at this time!'
                                             'Created by @beksultandai ', reply_markup=keyboard1)


@domain_bot.message_handler(commands=['help'])
def help(message):
    return start_message(message)


@domain_bot.message_handler(regexp="[a-m]")
def find_domain(message):
    # global domain_names
    domain_names = message.text;
    ssl_certificate_exp = '';
    chek_domain = whois.whois(domain_names)
    exp_date = chek_domain.expiration_date
    if exp_date is None:
        try:
            print(chek_domain.creation_date)
            try:
                ssl_connection_setting = Context(SSLv3_METHOD)
            except ValueError:
                ssl_connection_setting = Context(TLSv1_2_METHOD)
            ssl_connection_setting.set_timeout(5)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((domain_names, 443))
                c = Connection(ssl_connection_setting, s)
                c.set_tlsext_host_name(str.encode(domain_names))
                c.set_connect_state()
                c.do_handshake()
                cert = c.get_peer_certificate()
                print("Is Expired: ", cert.has_expired())
                if cert.has_expired() == False:
                    ssl_certificate_exp = "\nСертификат действительный"
                else:
                    ssl_certificate_exp = '\nСертификат не действительный'
                print("Issuer: ", cert.get_issuer())
                subject_list = cert.get_subject().get_components()
                cert_byte_arr_decoded = {}
                for item in subject_list:
                    cert_byte_arr_decoded.update({item[0].decode('utf-8'): item[1].decode('utf-8')})
                print(cert_byte_arr_decoded)
                if len(cert_byte_arr_decoded) > 0:
                    print("Subject: ", cert_byte_arr_decoded)
                if cert_byte_arr_decoded["CN"]:
                    print("Common Name: ", cert_byte_arr_decoded["CN"])
                end_date = datetime.strptime(str(cert.get_notAfter().decode('utf-8')), "%Y%m%d%H%M%SZ")
                print("Not After (UTC Time): ", end_date)
                diff = end_date - datetime.now()
                print('Summary: "{}" SSL certificate expires on {} i.e. {} days.'.format(domain_names, end_date, diff.days))
                stay_not_date = "пусто, нет получилось получить данные"

                send_info1 = ssl_certificate_exp + '\nСрок действия SSL-сертификата истекает в:'+'\n' + str(end_date) +'\nСрок сертификата: '+ str(diff.days)+'Дней'
                send_info = "Домен " + str(chek_domain.domain_name).lower() + '\nДата регистрации ' + str(
                    chek_domain.creation_date) + '\nКоличество дней до продления: ' + stay_not_date + send_info1
                domain_bot.send_message(message.from_user.id, text=send_info)
        except:
            missing = "Ошибка подключения к ".format(domain_names)
            domain_bot.send_message(message.from_user.id, text=missing)
        if chek_domain.creation_date and chek_domain.expiration_date is None:
            stay_not_date = "пусто, нет получилось получить все данные"
            stay_empty = "пусто"
            try:
                print(chek_domain.creation_date)
                try:
                    ssl_connection_setting = Context(SSLv3_METHOD)
                except ValueError:
                    ssl_connection_setting = Context(TLSv1_2_METHOD)
                ssl_connection_setting.set_timeout(5)
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect((domain_names, 443))
                    c = Connection(ssl_connection_setting, s)
                    c.set_tlsext_host_name(str.encode(domain_names))
                    c.set_connect_state()
                    c.do_handshake()
                    cert = c.get_peer_certificate()
                    print("Is Expired: ", cert.has_expired())
                    if cert.has_expired() == False:
                        ssl_certificate_exp = "\nСертификат действительный"
                    else:
                        ssl_certificate_exp = '\nСертификат не действительный'
                    print("Issuer: ", cert.get_issuer())
                    subject_list = cert.get_subject().get_components()
                    cert_byte_arr_decoded = {}
                    for item in subject_list:
                        cert_byte_arr_decoded.update({item[0].decode('utf-8'): item[1].decode('utf-8')})
                    print(cert_byte_arr_decoded)
                    if len(cert_byte_arr_decoded) > 0:
                        print("Subject: ", cert_byte_arr_decoded)
                    if cert_byte_arr_decoded["CN"]:
                        print("Common Name: ", cert_byte_arr_decoded["CN"])
                    end_date = datetime.strptime(str(cert.get_notAfter().decode('utf-8')), "%Y%m%d%H%M%SZ")
                    print("Not After (UTC Time): ", end_date)
                    diff = end_date - datetime.now()
                    stay_not_date = "пусто, нет получилось получить данные"
                    send_info1 = ssl_certificate_exp + '\nСрок действия SSL-сертификата истекает в:'+'\n'+ str(
                        end_date) + '\nСрок сертификата: ' + str(diff.days) + 'Дней'
                    send_info = "Домен " + str(chek_domain.domain_name).lower() + '\nДата регистрации: ' + stay_empty + \
                                '\nКоличество дней до продления: ' + stay_empty + '\n' + stay_not_date + send_info1
                    domain_bot.send_message(message.from_user.id, text=send_info)
            except:
                missing = "Ошибка подключения к ".format(domain_names)
                domain_bot.send_message(message.from_user.id, text=missing)
    else:
        print(chek_domain.creation_date, ' \n ',chek_domain.expiration_date)
        time = datetime.now()
        d1 = datetime.strptime(str(time), '%Y-%m-%d %H:%M:%S.%f')
        d2 = datetime.strptime(str(exp_date), '%Y-%m-%d %H:%M:%S')
        full_date = str(d1 - d2)
        stay_time = full_date[1:-22] + ' дней или '
        stay_day = int(full_date[1:-22]) / 30
        stay_month = f'\n{int(stay_day)} Месяц (+ -)'
        try:
            try:
                ssl_connection_setting = Context(SSLv3_METHOD)
            except ValueError:
                ssl_connection_setting = Context(TLSv1_2_METHOD)
            ssl_connection_setting.set_timeout(5)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((domain_names, 443))
                c = Connection(ssl_connection_setting, s)
                c.set_tlsext_host_name(str.encode(domain_names))
                c.set_connect_state()
                c.do_handshake()
                cert = c.get_peer_certificate()
                print("Is Expired: ", cert.has_expired())
                if cert.has_expired() == False:
                    ssl_certificate_exp = "\nСертификат действительный"
                else:
                    ssl_certificate_exp = '\nСертификат не действительный'
                print("Issuer: ", cert.get_issuer())
                subject_list = cert.get_subject().get_components()
                cert_byte_arr_decoded = {}
                for item in subject_list:
                    cert_byte_arr_decoded.update({item[0].decode('utf-8'): item[1].decode('utf-8')})
                print(cert_byte_arr_decoded)
                if len(cert_byte_arr_decoded) > 0:
                    print("Subject: ", cert_byte_arr_decoded)
                if cert_byte_arr_decoded["CN"]:
                    print("Common Name: ", cert_byte_arr_decoded["CN"])
                end_date = datetime.strptime(str(cert.get_notAfter().decode('utf-8')), "%Y%m%d%H%M%SZ")
                diff = end_date - datetime.now()

                send_info1 = ssl_certificate_exp + '\nСрок действия SSL-сертификата истекает в:'+'\n'+str(end_date) + '\nСрок сертификата: '+str(diff.days)+'Дней'
                send_info = "Домен " + str(chek_domain.domain_name).lower() + '\nДата регистрации ' + str(
                    chek_domain.creation_date) + '\nКоличество дней до продления: ' + stay_time + stay_month + send_info1
                domain_bot.send_message(message.from_user.id, text=send_info)
        except:
            missing = "Ошибка подключения к ".format(domain_names)
            domain_bot.send_message(message.from_user.id, text=missing)
            c.shutdown()
            s.close()


def all_information():
    pass


@domain_bot.message_handler(content_types=['text'])
def get_text_messages(message):
    if message.text == "Привет" or "Hello":
        domain_bot.send_message(message.from_user.id, 'Hello! I don"t understand you. Follow this command /help.')


domain_bot.polling(none_stop=True, interval=0)


