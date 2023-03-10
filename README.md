# Blockchain Database for Messenger

Представлено два варианта базы данных: с использованием алгоритма блочного шифрования AES-128 (Blockchain.py), и без него (Blockchain_without_encryption.py). Оба варианта имеют одинаковый набор функций, которые описаны ниже.


* Функция create_user(self, login, password, data=""): 
В функцию передаются следующие параметры: login, password, data. Где login – логин пользователя, password – его пароль. Оба параметра задает пользователь. Если пользователь с таким логином уже зарегистрирован в системе, функция вернет значение None. После успешной регистрации, каждому пользователю выдается уникальный токен. В параметр data пользователь передает доп. Информацию, которую бы хотел разместить на странице своего профиля.

* Функция sign_in(self, login, password):
В функцию передаются следующие параметры: login, password. Где login – логин пользователя, password – его пароль. Оба параметра задает пользователь. Если пароль от аккаунта соответствующего логина не подходит, функция вернет значение None.  Далее все действия на аккаунте происходят только в том случае, если токен для аккаунта верный.

* Функция send_message(self, login_from, login_to, message1, token):
В функцию передаются следующие параметры: login_from, login_to, message1, token. Где login_from – логин пользователя, который отправляет сообщение, login_to – логин пользователя, принимающего сообщение, message_1 – сообщение, передаваемое пользователем, token – токен пользователя, отправляющего сообщение. Функция выполняет отправку сообщения между пользователями.

* Функция get_messages(self, user1, user2, token, count):
В функцию передаются следующие параметры: user1, user2, token, count. Где user1 – логин пользователя, который отправляет сообщение, user2 – логин пользователя, принимающего сообщение, token – токен пользователя, count – количество сообщений, которое может видеть пользователь. Функция позволяет просмотреть count-ное количество сообщений, как принятых, так и отправленных.

* Функция set_user_data(self, login, token, data1):
В функцию передаются следующие параметры: login, token, data1. Где login – логин пользователя, token – его токен, data1 – информация, переданная пользователем. Функция позволяет менять информацию о пользователе для последующего отображения ее на странице профиля.

* Функция get_user_data(self, login, token):
В функцию передаются следующие параметры: login, token. Где login – логин пользователя, token – его токен. Функция позволяет просматривать информацию о пользователе на странице профиля.

* Функция get_connections(self, login, token):
В функцию передаются следующие параметры: login, token. Где login – логин пользователя, token – его токен. Функция возвращает список пользователей, с которыми у передаваемого пользователя есть общие сообщения.

* Функция is_exist(self, login, token):
В функцию передаются следующие параметры: login, token. Где login – логин пользователя, token – его токен. Функция определяет, существует ли в базе данных пользователь с указанным логином.

* Функция get_users(self):
Функция выводит список всех зарегистрированных в базе данных пользователей.
