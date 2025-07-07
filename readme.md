1. 
- В докере создается БД authentification и собирается код
- Добавлена отдельная страница для создания GUID (uuid) пользователя /register 
- access токен формата sha-512 (HMAC-SHA512)
2. 
- так как тестовый репозиторий не стал добавлять .env в гитигнор
3. 
- Запускать командой: docker-compose -f docker-compose.yml up -d 
- 
- Пересобирать проект: docker-compose down && docker-compose up -d --build --force-recreate --no-deps

4. 
- register login используются для создания пользователя и входа в систему

- Остальные, так или иначе, используют мидлвейр с проверкой авторизации
5. 
- register используется для получения uuid, требует поле "email"

- login используется для получения access и refresh, требует поле "uuid"

- refresh требует авторизации (параметр header: Authorisation "Bearer `<token>`") и параметр body "refresh"

- logout деавторизует пользователя, требует авторизации (параметр header: Authorisation "Bearer `<token>`")

- about получает информацию о пользователе из базы зарегистрированных пользователей, требует авторизации (параметр header: Authorisation "Bearer `<token>`").