class Aes:
    def __init__(self, name: str = "Aes") -> None:
        self.name = name

    def respond(self) -> str:
        return f"Hello, {self.name}!"