!!! quote "Changes in sing-box 1.10.0"

    :material-plus: `type: inline`

# rule-set

!!! question "Since sing-box 1.8.0"

### Structure

=== "Inline"

    !!! question "Since sing-box 1.10.0"

    ```json
    {
      "type": "inline", // optional
      "tag": "",
      "rules": []
    }
    ```

=== "Local File"

    ```json
    {
      "type": "local",
      "tag": "",
      "format": "source", // or binary, text, yaml or auto
      "path": ""
    }
    ```

=== "Remote File"

    !!! info ""
    
        Remote rule-set will be cached if `experimental.cache_file.enabled`.

    ```json
    {
      "type": "remote",
      "tag": "",
      "format": "source", // or binary, text, yaml or auto
      "url": "",
      "download_detour": "", // optional
      "update_interval": "" // optional
    }
    ```

### Fields

#### type

==Required==

Type of rule-set, `local` or `remote`.

#### tag

==Required==

Tag of rule-set.

### Inline Fields

!!! question "Since sing-box 1.10.0"

#### rules

==Required==

List of [Headless Rule](./headless-rule/).

### Local or Remote Fields

#### format

==Required==

Format of rule-set file: `source`, `binary`, `text`, `yaml` or `auto`.

The `text` format accepts one domain suffix, IP address or CIDR prefix per line. Empty lines, `#` comments and `//` comments are ignored.

The `yaml` format accepts Clash/Mihomo rule-provider files with a top-level `payload` sequence. Domain, IP CIDR and classical domain/IP/port/process/network items that map directly to sing-box headless rules are supported; unsupported items reject the file instead of being ignored. `auto` detects SRS binary, sing-box source JSON, Clash/Mihomo YAML and text content without relying on the file extension.

Optional when `path` or `url` uses `json`, `srs`, `txt`, `yaml` or `yml` as extension.

### Local Fields

#### path

==Required==

!!! note ""

    Will be automatically reloaded if file modified since sing-box 1.10.0.

File path of rule-set.

### Remote Fields

#### url

==Required==

Download URL of rule-set.

#### download_detour

Tag of the outbound to download rule-set.

Default outbound will be used if empty.

#### update_interval

Update interval of rule-set.

`1d` will be used if empty.
