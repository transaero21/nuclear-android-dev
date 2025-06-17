# Домашнее Задание №4

## Условие

- Реализовать приложение, которое использует все компоненты
  - В каждом из компонентов добавить логирование на первый вызываемый метод
  - Ответить на вопрос, какой компонент запускается в Android-приложении раньше остальных и почему

- Найти, где находится вызов функции main в Android-приложении

## Запуск компонентов

Основные компоненты - Activities, Services, Broadcast receivers, Content providers.
Все эти компоненты могут быть входными точками и в зависимости от цели каждое будет вызываться раньше или позже других, или не будет вовсе.
Важно учесть, что Application будет вызываться всегда перед запуском всех входных точек.

Для того чтобы собрать логи по тегу для анализа:
```bash
adb logcat -s "EntryPoints"
```

Для того чтобы завершить приложение:
```bash
adb shell am force-stop ru.transaero21.hw04
```

### Activities

```bash
adb shell am start -n ru.transaero21.hw04/.Activity
```

```
I EntryPoints: ContentProvider onCreate()
I EntryPoints: Application onCreate()
I EntryPoints: Activity onCreate()
```

### Services

Могут возникнуть проблемы с фоновым запуском на разных версиях Android и разных модификациях

```bash
adb shell am startservice -n ru.transaero21.hw04/.Service
```

```
I EntryPoints: ContentProvider onCreate()
I EntryPoints: Application onCreate()
I EntryPoints: Service onStartCommand()
```

### Broadcast receivers

```bash
adb shell am broadcast -n ru.transaero21.hw04/.BroadcastReceiver -a android.intent.action.BOOT_COMPLETED
```

```
I EntryPoints: ContentProvider onCreate()
I EntryPoints: Application onCreate()
I EntryPoints: BroadcastReceiver onReceive()
```

### Content providers

```bash
adb shell content query --uri content://ru.transaero21.hw04.provider/
```

```
I EntryPoints: ContentProvider onCreate()
I EntryPoints: Application onCreate()
I EntryPoints: ContentProvider query()
```

### Выводы

Очевидно, что Content provider всегда запускался первым.
Можно предположить, что провайдер должен быть готовым до любых обращений к данным, включая вызовы от других компонентов.
К тому же как видно, он всегда создаёт автоматически при вызове любых компонентов

## Поиск main функции

В Android приложении нет явной функции main.

Точкой входа в приложение является класс [ActivityThread](https://android.googlesource.com/platform/frameworks/base/+/master/core/java/android/app/ActivityThread.java)
1. Когда система запускает приложение, она создает процесс и вызывает метод main() класса ActivityThread
2. Этот метод инициализирует главный цикл сообщений (Looper) и начинает обработку сообщений системы
3. Затем система создает экземпляр компонентов приложения
