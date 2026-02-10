# DVD Ripper Web Interface

The DVD Ripper includes a modern web interface for managing ripping operations through a browser. The web daemon runs as a standalone service and communicates with the `rip` CLI tool.

## Running the Web Interface

Start the web daemon:

```bash
rip web --port 8080 --storage ~/Videos
```

Then open your browser to: `http://localhost:8080`

## Command Line Options

- `--port` or `-p` (default: 8080): Port to run the web server on
- `--storage` (default: ~/Videos): Storage path for ripped media and categories
- `--rip` (default: rip): Path to the rip CLI command (if not in PATH)

### Examples

```bash
# Run on custom port
rip web --port 9000

# Use custom storage location
rip web --port 8080 --storage /plex/storage

# Specify custom rip CLI path
rip web --port 8080 --rip /usr/local/bin/rip
```

## Features

### Start Rip Tab
- **DVD Device Detection**: Automatically discovers connected DVD drives
- **Movie Name Lookup**: Automatically looks up movie information in TMDB
- **Category Management**: Select from existing categories or create new ones
- **Background Processing**: Rip jobs run asynchronously without blocking the UI

### Settings Tab
- **Application Settings**: View storage path and rip command location
- **makemkvcon Options**: Configure minimum title length and preferred format
- **Transcoding Settings**: Enable/disable transcoding with codec and bitrate selection
- **Local Storage**: Settings are saved in browser localStorage

## Jellyfin-Inspired Design

The interface uses Jellyfin's color scheme:
- Primary: `#00a4dc` (Jellyfin Blue)
- Accent: `#a335ee` (Jellyfin Purple)
- Dark Background: `#1c1c1c`
- Light Text: `#e0e0e0`

## Theme Assets

Custom icons and the DVDRipTitle logo are stored in `web/assets/`:
- `DVDRipTitle.png` - Main logo
- `start rip.png` - Start rip icon
- `category.png` - Category icon
- `settings.png` - Settings icon
- `analyze.png` - Analysis icon
- `transcode.png` - Transcoding icon
- `complete.png` - Completion icon
- `load.png` - Loading icon
- `destination folder.png` - Destination folder icon
- `Other Options.png` - Additional options icon

## Storage Path Structure

The web interface manages categories as directories in your storage path. For example, with `--storage /plex/storage`:

```
/plex/storage/
├── Drama/
│   ├── The Break-Up (2006)/
│   │   └── The Break-Up (2006).mkv
│   └── Another Movie (2020)/
│       └── Another Movie (2020).mkv
├── Comedy/
│   └── ...
└── Action/
    └── ...
```

When you specify a movie name and category, the ripped file will be organized into:
`/plex/storage/<category>/<MovieName YYYY>/`

## API Endpoints

The web daemon provides RESTful API endpoints:

### GET `/api/devices`
Returns available DVD devices:
```json
{
  "devices": ["/dev/sr0", "/dev/rdisk6"]
}
```

### GET `/api/categories`
Returns all categories:
```json
{
  "categories": ["Drama", "Comedy", "Action"]
}
```

### POST `/api/categories`
Create a new category:
```json
{
  "name": "Horror"
}
```

### PUT `/api/categories`
Rename a category:
```json
{
  "oldName": "Old Name",
  "newName": "New Name"
}
```

### DELETE `/api/categories`
Delete a category:
```json
{
  "name": "Category Name"
}
```

### POST `/api/rip`
Start a rip job:
```json
{
  "device": "/dev/sr0",
  "category": "Drama",
  "movie": "The Shawshank Redemption"
}
```

### GET `/api/status`
Get daemon status:
```json
{
  "status": "running",
  "storagePath": "/plex/storage",
  "ripCommand": "rip",
  "availableDevices": ["/dev/sr0"]
}
```

## Settings Persistence

Settings are stored in the browser's localStorage and include:
- `makemkvMinimumLength` - Minimum title duration
- `makemkvPreferredFormat` - Output format (mkv or m2ts)
- `transcodingEnabled` - Transcoding on/off
- `transcodingCodec` - Video codec (h264, h265, vp9)
- `transcodingBitrate` - Video bitrate in kbps

## Running as a System Daemon

### macOS (launchd)

Create `~/Library/LaunchAgents/com.rmasci.rip-web.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.rmasci.rip-web</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/rip</string>
        <string>web</string>
        <string>--port</string>
        <string>8080</string>
        <string>--storage</string>
        <string>/plex/storage</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/var/log/rip-web.err.log</string>
    <key>StandardOutPath</key>
    <string>/var/log/rip-web.out.log</string>
</dict>
</plist>
```

Load with:
```bash
launchctl load ~/Library/LaunchAgents/com.rmasci.rip-web.plist
```

### Linux (systemd)

Create `/etc/systemd/system/rip-web.service`:

```ini
[Unit]
Description=DVD Ripper Web Interface
After=network.target

[Service]
Type=simple
User=nobody
ExecStart=/usr/local/bin/rip web --port 8080 --storage /plex/storage
Restart=always
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl daemon-reload
sudo systemctl enable rip-web
sudo systemctl start rip-web
```

## Reverse Proxy Setup (nginx)

To run behind nginx:

```nginx
server {
    listen 80;
    server_name media.example.com;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Troubleshooting

**Port already in use?**
```bash
# Find and kill the process using the port
lsof -ti :8080 | xargs kill -9
```

**No devices found?**
- Ensure the DVD drive is connected and powered on
- Check permissions on `/dev/sr*` (Linux) or `/dev/rdisk*` (macOS)
- On Linux: `sudo chmod 666 /dev/sr0`

**Rip job fails?**
- Ensure `rip` CLI tool is in PATH
- Check that storage path exists and is writable
- Verify DVD is inserted and readable

**Settings not saving?**
- Check that browser localStorage is enabled
- Clear browser cache and try again
