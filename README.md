# auth-jwt-assignment

Тестовое задание на позицию Junior Backend Developer в MEDODS

## Quickstart

Как требовалось в [ТЗ](https://medods.yonote.ru/share/1982193d-43fc-4075-a608-cc0687c5eac2/doc/testovoe-zadanie-na-poziciyu-junior-backend-developer-6iFFklIyMI), проект запускается одной командой: `docker-compose -f docker-compose.yml up -d`.

Сервер находится по адресу http://localhost:8080/

## Эндпоинты

1. http://localhost:8080/swagger/index.html
    
    Swagger-документация сервиса
2. http://localhost:8080/auth/{guid}/login

    Авторизация пользователя с GUID `guid` (см. [Swagger-документацию](http://localhost:8080/swagger/index.html))
3. http://localhost:8080/auth/{guid}/logout

    Деавторизация пользователя (см. [Swagger-документацию](http://localhost:8080/swagger/index.html))
4. http://localhost:8080/auth/{guid}/refresh

    Обновление пары токенов для пользователя с GUID `guid` (см. [Swagger-документацию](http://localhost:8080/swagger/index.html))
5. http://localhost:8080/whoami

    Защищенный эндпоинт, возвращающий GUID авторизованного пользователя (см. [Swagger-документацию](http://localhost:8080/swagger/index.html))

   

## Токены авторизации

Токены хранятся в cookies клиента.

### Access Token
**JWT** токен подписанный по алгоритму **HMAC** с хэш-функцией **SHA-512**.

#### Тело токена:
```golang
type AccessToken struct {
	ID             string    // jti
	UserGUID       string    // sub
	ExpiresAt      time.Time // exp
	RefreshTokenID string    // rtid: необходим для проверки на единовременный выпуск с Refresh-токеном 

	WebToken string // Не лежит в теле
}
```

### Refresh Token

Клиент хранит `base64` значение токена.

БД хранит `bcrypt` хэш токена.

#### Генерация токена
1. Генерируем id токена: **`TokenID`**
2. Генерируем рандомным образом значение токена: **`RawToken`**
3. `bcrypt`-хэшируем значение **`RawToken`**: **`TokenHash`**
4. В БД храним **`TokenHash`**
5. Клиенту отправляем `Base64.Encode("{TokenID}:{RawToken}")` (псевдокод)

#### Валидация токена
1. Декодируем "сырой" токен с клиента: `Base64.Decode(tokenB64)` (псевдокод).
2. Пробуем достать **`TokenID`** и **`RawToken`** из полученной в *шаге 1* строки.
3. В случае успеха *шага 2* пробуем достать из БД Refresh Token с совпадающим **`TokenID`**.
4. В случае успеха *шага 3* проверяем, совпадает ли `bcrypt` хэш **`RawToken`**. 
5. В случае успеха *шага 4* токен считается **валидным**, в случае неуспеха любого из предыдущих шагов токен считается **невалидным**

## Кое-что не успел
1. Покрыть тестами;
2. Написать graceful shutdown для сервера, где отслеживался бы статус отправленных запросов на webhook.

## Вопросы к ТЗ

### 1. Вид GUID на авторизацию

В каком виде приходит GUID на роут авторизации: query-параметром (напр. `.../login?guid=$GUID`), в составе пути URL (напр. `.../{GUID}/login`), в теле запроса, в хэдере Authorization или другими способами (_ref_: <q>...получение пары токенов (access и refresh) для пользователя с идентификатором (GUID) указанным в параметре запроса</q>)?

#### Решение

GUID является составляющей пути запроса: `POST /auth/{GUID}/login`

### 2. Доступ для одного пользователя (GUID) через разные web-клиенты

При деавторизации пользователя, в случае когда UserAgent не совпадает, должны ли мы деавторизовать **все** web-клиенты, или только **тот клиент, с которого приходит запрос** (клиент определяем по паре значений `user_guid` + `ip`)

#### Решение

Деавторизуем пользователя с `user_guid` + `ip`

### 3. Требование к `refresh` токену

Требование к `refresh` токену <q>Токен должен быть защищен от изменений на стороне клиента</q> подразумевает под собой невозможность его изменения _javascript_ скриптом или что-то ещё?

#### Решение

Храним токены в cookies клиента со установленным атрибутом `httpOnly: true`
