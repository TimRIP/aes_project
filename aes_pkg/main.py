from aes_pkg import Aes
import argparse

def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("-n", "--name", default="World")
    args = p.parse_args(argv)
    print(f"Hello, {args.name}!")
    
    greeter = Aes("yahhh this works")      # ← use your class
    print(greeter.respond())

if __name__ == "__main__":
    # This runs when you execute: python -m aes_pkg.main
    main()