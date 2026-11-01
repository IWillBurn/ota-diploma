# Render the thesis SVG figures to PNG (2x) for the Word build, with headless Edge.
#   powershell -File docs/thesis/tools/render_figures.ps1
# The in-figure captions ("Рис. N.N. ...") are removed: the Word build adds a GOST caption below each figure.
$ErrorActionPreference = "Continue"
$root = Resolve-Path "$PSScriptRoot\..\..\.."
$src = Join-Path $root "docs\figures"
$out = Join-Path $root "docs\thesis\build\figures"
New-Item -ItemType Directory -Force $out | Out-Null
$edge = @("C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
          "C:\Program Files\Microsoft\Edge\Application\msedge.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
$utf8 = New-Object System.Text.UTF8Encoding $false
foreach ($svg in Get-ChildItem $src -Filter *.svg) {
    $raw = [IO.File]::ReadAllText($svg.FullName, [Text.Encoding]::UTF8)
    $clean = [regex]::Replace($raw, "<text[^>]*>\u0420\u0438\u0441\. [^<]*</text>", "")
    $tmp = Join-Path $out ("_" + $svg.Name)
    [IO.File]::WriteAllText($tmp, $clean, $utf8)
    $head = $raw.Substring(0, 400)
    $w = [math]::Ceiling([double]([regex]::Match($head, "width='([0-9.]+)'").Groups[1].Value))
    $h = [math]::Ceiling([double]([regex]::Match($head, "height='([0-9.]+)'").Groups[1].Value))
    $png = Join-Path $out ($svg.BaseName + ".png")
    & $edge --headless=new --disable-gpu --hide-scrollbars --force-device-scale-factor=2 `
        --screenshot="$png" --window-size="$w,$h" ("file:///" + ($tmp -replace '\\', '/')) 2>$null | Out-Null
    Start-Sleep -Milliseconds 1500
    Remove-Item $tmp
    "{0} -> {1} ({2}x{3})" -f $svg.Name, $png, $w, $h
}
