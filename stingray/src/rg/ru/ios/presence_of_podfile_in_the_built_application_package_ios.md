# Наличие файла со списком сторонних зависимостей в собранном пакете приложения

<table class='noborder'>
    <colgroup>
      <col/>
      <col/>
    </colgroup>
    <tbody>
      <tr>
        <td rowspan="2"><img src="../../../img/defekt_info.png"/></td>
        <td>Критичность:<strong> ИНФО</strong></td>
      </tr>
      <tr>
        <td>Способ обнаружения:<strong> DAST, SENSITIVE INFO, FILES</strong></td>
      </tr>
    </tbody>
</table>

## Описание

В среде iOS существует несколько систем сборки зависимостей проекта со специфическими типами конфигурационных файлов, их наименованиями и содержанием. В сборке приложения может оказаться такой файл с описанием применяемых сторонних библиотек и их версий. Список таких систем и их файлов представлен в таблице.

Система управления зависимостями|Названия конфигурационных файлов
-|-
CocoaPods|Podfile, Podfile.lock, Manifest.lock
Carthage|Cartfile, Cartfile.resolved, Cartfile.private
SwiftPM|Package.swift, Package@swift-{version}.swift
Accio|Совпадают с SwiftPM 
Athena|build.gradle, build.gradle.kts, settings.gradle.kts
Mint|Mintfile
Rome|Romefile
SWM|swiftmodule.json
Xcode Maven|pom.xml

Наличие одного из перечисленных конфигурационных файлов может помочь в определении уязвимости в используемых библиотеках, а также раскрыть информацию о внутренних репозиториях (если используются внутренние компоненты).

## Рекомендации

Рекомендуется исключить файлы, которые не требуются для работы приложения, из финальной сборки.

1. Если отсутствует файл пользовательских настроек для сборки, необходимо его создать.

    <figure markdown>
    ![](../../img/image4.png)
    </figure>

2. Добавить ключ настройки **EXCLUDED_SOURCE_FILE_NAMES**, если он отсутствует.

    <figure markdown>
    ![](../../img/image5.png)
    </figure>

3. Добавить настройки, определяющие, какие файлы и папки необходимо исключить из финальной сборки приложения.

    <figure markdown>
    ![](../../img/image6.png)
    </figure>