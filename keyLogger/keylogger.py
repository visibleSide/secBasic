from pyinput import keyboard
def on_press(key):
    print("key {} pressed".format(key))

def on_release(key):
    print("Key {} released".format(key()))

    if str(key)=='key.esc':
        print("Exiting...")
        return False
with keyboard.Listener(
    on_press = on_press
    on_release = on_release) as Listener:
    listener.join()    