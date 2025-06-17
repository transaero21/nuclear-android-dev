# Домашнее Задание №6

## Условие

1. Получить премиум сообщение в `Task 1.apk`
   - Bonus: в `Task 1 Extra.apk`

2. Реализовать вывод любого диалогового окна при старте Telegram
   - Bonus: снять ограничение на скриншоты в приватных чатах Telegram

## Патчинг APK

### Простое

Для анализа APK загрузим его в jadx.
Используя поиск по коду найдём строку `standart-user`, это единственное использование:

```java
MainActivityKt.Greeting(Data.INSTANCE.isPrem() ? "standard user" : "Winner", PaddingKt.padding(Modifier.INSTANCE, innerPadding), $composer, 0, 0);
```

Очевидно, нужно изменить работу метода `isPrem`, заглянем в класс `Data`:

```java
public final class Data {
    public static final int $stable = 0;
    public static final Data INSTANCE = new Data();
    private static final boolean isPrem = INSTANCE.isPremium();

    private Data() {
    }

    public final boolean isPrem() {
        return isPrem;
    }

    private final boolean isPremium() {
        return false;
    }
}
```

Очевидно, что нужно изменить возвращаемое значение метода `isPremium`, теперь воспользуемся apktool и отредактируем smali:

```diff
.method private final isPremium()Z
    .registers 2

    .line 7
-    const/4             v0, 0
+    const/4             v0, 1
    return              v0
    
.end method
```

### Сложное

Проанализировав, можно сделать вывод, что APK сильно обфусцирован, но всё равно можно найти участок кода со строкой `standart-user`

```java
n1.a.a("standard user", androidx.compose.foundation.layout.a.a(nVar), c0338o, 0, 0);
```

Однако найти `Winner` не получится, возникает предположение, что тут необходимо просто поменять строку.
Из-за того, что сначала был загружен решённый вариант, то я имею возможность сравнить весь контент, что и подтверждает мою теорию.
Поэтому просто воспользуемся apktool и отредактируем строку smali:

```diff
    .line 50
    move-result-object  v2
    .line 51
-    const-string        v4, "standard user" # string@16fe
+    const-string        v4, "Winner" # string@16fe
    .line 53
    const/4             v0, 0
    .line 54
    invoke-static       {v4, v2, v3, v0, v0}, Ln1/a;->a(Ljava/lang/String;, LG/l;, Lv/o;, I, I)V # method@1a05
```

## Использование Frida

Установленный пакет Telegram - `org.telegram.messenger.web`

### Вывод диалогового окна

Для решения задачи напишем скрипт `open_alert_dialog.js`.
Важный момент, который стоит упомянуть: для передачи строки было необходимо её обернуть в соответствующий Java класс, иначе строка из JS не конвертируется.

Код для запуска:

```bash
frida -U -f org.telegram.messenger.web -l open_alert_dialog.js
```

### Снятие запрета 

Для решения задачи напишем скрипт `disable_flag_secure.js`.
Сначала вспомним, как можно в принципе запретить делать скриншоты: необходимо установить флаг `WindowManager.LayoutParams.FLAG_SECURE` или воспользоваться методом `setSecure`.
Так как клиент Telegram на Android имеет открытый исходный код, то мы в принципе можем проверить, [что используется конкретно](https://github.com/search?q=repo%3ADrKLO%2FTelegram+%28setSecure+OR+FLAG_SECURE%29&type=code).

Поэтому ограничим методы, которые могу этот флаг установить:
- Методы класса `Window`:
  - `setFlags` - используется, например в `BubbleActivity`, не требуется
  - `addFlags` - используется, например в `FlagSecureReason`, то есть при входе в секретный чат
  - `setAttributes` - не используется
- Методы класса `SurfaceView`:
  - `setSecure` - используется, например в `StoryViewer`, не требуется
- Методы интерфейса `WindowManager`, класса `WindowManagerImpl`:
  - `addView` - используется, например в `SecretMediaViewer`, то есть при открытии фото в секретном чате, и не только

Код для запуска:

```bash
frida -U -f org.telegram.messenger.web -l disable_flag_secure.js
```
