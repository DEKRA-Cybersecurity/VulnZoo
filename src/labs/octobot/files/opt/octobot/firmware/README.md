# OctoBot firmware drop

The lab flashes `robot_arm.hex` to the Arduino at deploy (`40-octobot-flash-firmware.sh`)
or at runtime via the OTA endpoint (`POST /update`, `IoT:I4`).

`robot_arm.hex` is **not** committed: it is a build artifact. Generate it on a PC
from the patched sketch and drop it here before packaging the lab.

```sh
# from the repo root, after the Section 4 serial patch is in the sketch
arduino-cli core install arduino:avr
arduino-cli compile --fqbn arduino:avr:uno \
  --output-dir /tmp/octobot-fw \
  "src/labs/octobot/arduino_stuff/Youfang Smart-ARM-code-v1.71-joystick"
cp /tmp/octobot-fw/*.ino.hex \
  src/labs/octobot/files/opt/octobot/firmware/robot_arm.hex
```

The patched sketch (with the `Sx:angle` serial parser) lives at
`labs/octobot/arduino_stuff/Youfang Smart-ARM-code-v1.71-joystick/`.

With no Arduino attached (`use_real_hardware=0`), the serial bus simulates the
arm, so the lab runs without this file.
