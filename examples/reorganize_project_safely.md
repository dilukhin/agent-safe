# Example: safe project reorganization

```bash
safe checkpoint --reason "before LanFabric tree reorganization"
safe fs-move ./LanFabric ./LanFabricRoot/LanFabric --reason "move repository into new root"
safe status
```

If destination exists, `safe fs-move` refuses to run, avoiding PowerShell-style accidental nesting.
