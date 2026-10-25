# VPN routing rules

Селективная маршрутизация: **VPN только для явно перечисленных сервисов, всё остальное DIRECT**. Неуказанный трафик идёт через интернет-провайдера устройства, не через VPN-ноду.

## Shadowrocket

[Постоянная ссылка на vpn_rules.conf](https://raw.githubusercontent.com/Alesnyt/vpn_rules/main/vpn_rules.conf)

В Shadowrocket обновить конфигурацию по ссылке и выбрать режим **Config / Конфигурация**. DIRECT действует на устройстве: трафик не проходит через RU, FR или KZ. Режим глобального прокси отменяет эту селективную маршрутизацию.

### Прямой доступ к российским и СНГ-сервисам

Явные DIRECT-правила охватывают домены и все их поддомены:

`su`, `xn--p1ai`, `moscow`, `ya.cc`, `yandex.com`, `yandex.net`, `yango.com`, `vk.com`, `vk.cc`, `mvk.com`, `mycdn.me`, `my.com`, `my.games`, `ok.me`, `kaspersky.com`, `ozon.com`, `ozon.by`, `ozon.kz`, `wildberries.by`, `wildberries.kz`, `2gis.com`, `magnit.com`, `fix-price.com`, `x5.tech`, `megafon.com`, `moex.com`, `okko.tv`, `okko.sport`, `boosty.to`, `lenta.com`, `premier.one`, `hh.by`, `hh.kz`, `mosmetro.tech`, `avs.io`.

**`meduza.io` и его поддомены — PROXY**, через выбранный VPN-профиль. Существующие явные PROXY-исключения (например, `google.ru`) имеют приоритет перед общими DIRECT-зонами. Всё остальное по-прежнему DIRECT по умолчанию.

### AgentRouter через VPN

`agentrouter.org` и все его поддомены (API, портал, документация, статика) — PROXY. Также добавлены LinuxDO OAuth (`linux.do` с поддоменами), точные хосты Umami (`cloud.umami.is`, `gateway.umami.is`, `eu.umami.is`, `api-gateway.umami.dev`, `api-gateway-eu.umami.dev`) и обнаруженный ресурс `lf3-static.bytednsdoc.com`. Используемые GitHub OAuth и Google Tag Manager уже покрыты прежними PROXY-правилами. Общие CDN целиком не перенаправляются. Состав проверен по публичной странице, настройкам входа и файлам приложения; новые внешние зависимости могут потребовать дополнения списка.

## Happ — пользовательские обновляемые списки

[Установка, обновления и отключение](happ/REMOTE.md)

[Первичная установка AlexClubs Selective](https://raw.githubusercontent.com/Alesnyt/vpn_rules/happ-data/IMPORT-HAPP.txt) — открыть в браузере, скопировать **содержимое страницы, не HTTPS-адрес**, затем импортировать маршрутизацию из буфера в Happ и выбрать свои серверы.

[Текущие списки для просмотра](https://raw.githubusercontent.com/Alesnyt/vpn_rules/happ-data/rules.json)

Это публичные правила, **не VPN-подписка**. Учётных данных и доступа к VPN эти файлы не предоставляют.

### Обновления

Редактировать **vpn_rules.conf** в ветке `main`, как для Shadowrocket. GitHub Actions проверит изменения и соберёт внешние GeoSite/GeoIP-списки в ветке `happ-data`. Happ получает их по постоянным адресам через обновление геофайлов; повторно импортировать профиль при изменении доменов/IP не требуется.

**Автообновление через подписку Happ:** серверный таймер проверяет GitHub дважды в сутки: в 09:00 и 21:00 по Москве и передаёт [SUBSCRIPTION-HAPP.txt](https://raw.githubusercontent.com/Alesnyt/vpn_rules/happ-data/SUBSCRIPTION-HAPP.txt) в заголовке `Routing`. Это тот же профиль с именем AlexClubs Selective и меткой версии `LastUpdated`; DNS и маршруты не меняются. На iPhone для подписки AlexClubs включить автообновление и «Обновить при открытии». При новой версии Happ скачает GeoSite/GeoIP по сохранённым адресам. Настройка конкретного сервера и проверка телефона описаны в [инструкции](happ/REMOTE.md#автообновление-через-подписку-alexclubs).

Используется `routing/add`, не `routing/onadd`; выбор активного профиля остаётся в Happ. Отдельный ручной импорт по IMPORT-HAPP.txt сохранён. Автообновление зависит от запуска и фоновой работы приложения; точное время в фоне iOS не гарантируется.

[Статус сборки](https://github.com/Alesnyt/vpn_rules/actions/workflows/happ-lists.yml). При ошибке сохраняется последняя опубликованная версия. Старый [статичный v1](happ/README.md) оставлен для истории и больше не является рекомендуемым способом установки.

**DNS-исключения Happ:** `dns.google` / `8.8.8.8` и `dns10.quad9.net` / `9.9.9.10` сохраняют прежний DIRECT. Конвертер исключает только эти точные IP из широких ASN-сетей PROXY, не весь Google. Остальные Google-домены и сети идут через VPN согласно исходнику. Настройки DNS и импортируемый профиль не меняются; действующему **AlexClubs Selective** достаточно обновить GeoSite/GeoIP и переподключиться. [Подробности и диагностика](happ/REMOTE.md#dns-и-широкие-правила-google).
