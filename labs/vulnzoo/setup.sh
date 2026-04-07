#!/bin/bash
# setup.sh — Configura un repositorio OpenWrt limpio (v24.10.3) con soporte
# Bluetooth para Raspberry Pi 3B+ y las funcionalidades del proyecto VulnZoo.
#
# Uso: ./setup.sh /ruta/al/repo/openwrt-limpio
#
# Este script debe estar alojado junto a:
#   files/        — Archivos del rootfs (firmware BT, init scripts, webapp)
#   .config       — Configuración de build

set -euo pipefail

# ── Colores ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1" >&2; exit 1; }

# ── Validación de argumentos ─────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

if [ $# -ne 1 ]; then
    echo "Uso: $0 /ruta/al/repo/openwrt-limpio"
    exit 1
fi

TARGET_REPO="$(cd "$1" 2>/dev/null && pwd)" || err "La ruta '$1' no existe"

# Verificar que es un repo OpenWrt válido
[ -f "$TARGET_REPO/rules.mk" ] || err "'$TARGET_REPO' no parece un repositorio OpenWrt (falta rules.mk)"
[ -d "$TARGET_REPO/package" ]  || err "'$TARGET_REPO' no parece un repositorio OpenWrt (falta package/)"

# Verificar que los archivos fuente existen junto al script
[ -d "$SCRIPT_DIR/files" ]  || err "No se encuentra 'files/' junto al script"
[ -f "$SCRIPT_DIR/.config" ] || err "No se encuentra '.config' junto al script"

log "Repositorio destino: $TARGET_REPO"
log "Archivos fuente:     $SCRIPT_DIR"

# ── Paso 1: Limpiar estado del repo ─────────────────────────────────────────
log "Restaurando repositorio a estado limpio (git checkout)..."
cd "$TARGET_REPO"
git checkout -- . 2>/dev/null || warn "git checkout falló (puede que no sea un repo git)"

# ── Paso 2: Actualizar e instalar feeds ──────────────────────────────────────
log "Actualizando feeds..."
./scripts/feeds update -a || err "Fallo en feeds update"

log "Instalando feeds..."
./scripts/feeds install -a || err "Fallo en feeds install"

# ── Paso 3: Copiar files/ al repositorio ─────────────────────────────────────
log "Copiando files/ (firmware BT, init scripts, webapp, configs)..."
cp -a "$SCRIPT_DIR/files" "$TARGET_REPO/"

# ── Paso 4: Copiar .config ──────────────────────────────────────────────────
log "Copiando .config..."
cp "$SCRIPT_DIR/.config" "$TARGET_REPO/.config"

# ── Paso 5: Parchear other.mk — Habilitar CONFIG_BT_HCIUART_BCM ─────────────
log "Parcheando package/kernel/linux/modules/other.mk (CONFIG_BT_HCIUART_BCM=y)..."
OTHER_MK="$TARGET_REPO/package/kernel/linux/modules/other.mk"

if grep -q 'CONFIG_BT_HCIUART_BCM=n' "$OTHER_MK"; then
    sed -i 's/CONFIG_BT_HCIUART_BCM=n/CONFIG_BT_HCIUART_BCM=y/' "$OTHER_MK"
    log "  CONFIG_BT_HCIUART_BCM cambiado a =y"
elif grep -q 'CONFIG_BT_HCIUART_BCM=y' "$OTHER_MK"; then
    warn "  CONFIG_BT_HCIUART_BCM ya está en =y, no se modifica"
else
    warn "  No se encontró CONFIG_BT_HCIUART_BCM en other.mk"
fi

# Añadir btbcm.ko a FILES de kmod-bluetooth (necesario cuando btbcm se compila como módulo)
if ! grep -q 'btbcm\.ko' "$OTHER_MK"; then
    sed -i '/btmtk\.ko$/s|$| \\\n\t$(LINUX_DIR)/drivers/bluetooth/btbcm.ko|' "$OTHER_MK"
    log "  btbcm.ko añadido a FILES de kmod-bluetooth"
else
    warn "  btbcm.ko ya presente en other.mk"
fi

# ── Paso 6: Parchear distroconfig.txt — Liberar PL011 para Bluetooth ────────
log "Parcheando target/linux/bcm27xx/image/distroconfig.txt..."
DISTRO_CFG="$TARGET_REPO/target/linux/bcm27xx/image/distroconfig.txt"

if [ -f "$DISTRO_CFG" ]; then
    sed -i '/^\[pi3\]$/,/^\[/{
        s|^dtoverlay=disable-bt$|# Use PL011 UART (ttyAMA0) for Bluetooth - more reliable than Mini UART\n# miniuart-bt is disabled to allow proper Bluetooth operation\n# dtoverlay=miniuart-bt|
    }' "$DISTRO_CFG"

    sed -i '/^\[pi4\]$/,/^\[/{
        s|^dtoverlay=disable-bt$|dtoverlay=miniuart-bt|
    }' "$DISTRO_CFG"

    log "  [pi3]: disable-bt eliminado (PL011 libre para BT)"
    log "  [pi4]: disable-bt cambiado a miniuart-bt"
else
    warn "  distroconfig.txt no encontrado, saltando"
fi

# ── Paso 7: Parchear cmdline.txt — Quitar consola serial ────────────────────
log "Parcheando target/linux/bcm27xx/image/cmdline.txt..."
CMDLINE="$TARGET_REPO/target/linux/bcm27xx/image/cmdline.txt"

if [ -f "$CMDLINE" ]; then
    sed -i 's/ console=serial0,115200//' "$CMDLINE"
    log "  console=serial0 eliminado (PL011 libre para BT)"
else
    warn "  cmdline.txt no encontrado, saltando"
fi

# ── Paso 8: Verificar config-6.6 compartida ─────────────────────────────────
# La config compartida (target/linux/bcm27xx/config-6.6) debe mantenerse
# intacta. El git checkout del paso 1 la restaura, pero verificamos que
# no contenga opciones de arquitectura ARM 32-bit que indiquen corrupción.
log "Verificando target/linux/bcm27xx/config-6.6..."
SHARED_CFG="$TARGET_REPO/target/linux/bcm27xx/config-6.6"

if [ -f "$SHARED_CFG" ]; then
    if grep -q 'CONFIG_ARM=y' "$SHARED_CFG"; then
        warn "  config-6.6 compartida contiene CONFIG_ARM=y (posible corrupción)"
        log "  Restaurando desde git..."
        git checkout -- "$SHARED_CFG" 2>/dev/null || err "No se pudo restaurar config-6.6"
        log "  config-6.6 restaurada correctamente"
    else
        log "  config-6.6 correcta"
    fi
fi

# ── Paso 9: Regenerar config con dependencias ───────────────────────────────
log "Ejecutando make defconfig para resolver dependencias..."
make defconfig 2>&1 | grep -v '^WARNING' | tail -3

# ── Verificación final ──────────────────────────────────────────────────────
log "Verificando componentes Bluetooth..."
ERRORS=0

# Verificar paquetes BT en .config
for pkg in kmod-bluetooth bluez-daemon bluez-utils; do
    if grep -q "CONFIG_PACKAGE_${pkg}=y" "$TARGET_REPO/.config"; then
        log "  $pkg: habilitado"
    else
        warn "  $pkg: NO encontrado en .config"
        ERRORS=$((ERRORS + 1))
    fi
done

# Verificar firmware BT en files/
if [ -f "$TARGET_REPO/files/lib/firmware/brcm/BCM4345C0.hcd" ]; then
    log "  BCM4345C0.hcd: presente"
else
    warn "  BCM4345C0.hcd: NO encontrado en files/"
    ERRORS=$((ERRORS + 1))
fi

# Verificar init script
if [ -x "$TARGET_REPO/files/etc/init.d/brcm-bluetooth" ]; then
    log "  brcm-bluetooth init script: presente"
else
    warn "  brcm-bluetooth init script: NO encontrado en files/"
    ERRORS=$((ERRORS + 1))
fi

# Verificar CONFIG_BT_HCIUART_BCM
if grep -q 'CONFIG_BT_HCIUART_BCM=y' "$OTHER_MK"; then
    log "  CONFIG_BT_HCIUART_BCM=y: correcto"
else
    warn "  CONFIG_BT_HCIUART_BCM: NO habilitado"
    ERRORS=$((ERRORS + 1))
fi

# Verificar btbcm.ko en FILES de kmod-bluetooth
if grep -q 'btbcm\.ko' "$OTHER_MK"; then
    log "  btbcm.ko en FILES: correcto"
else
    warn "  btbcm.ko: NO presente en FILES de kmod-bluetooth"
    ERRORS=$((ERRORS + 1))
fi

# ── Resumen ──────────────────────────────────────────────────────────────────
echo ""
if [ $ERRORS -eq 0 ]; then
    log "===== Setup completado correctamente ====="
else
    warn "===== Setup completado con $ERRORS advertencias ====="
fi
echo ""
echo "  Archivos copiados:"
echo "    files/                → rootfs (firmware BT, init scripts, webapp)"
echo "    .config               → configuración de build"
echo ""
echo "  Parches aplicados:"
echo "    other.mk              → CONFIG_BT_HCIUART_BCM=y + btbcm.ko en FILES"
echo "    distroconfig.txt      → PL011 libre para Bluetooth en Pi 3"
echo "    cmdline.txt           → Sin consola serial (PL011 para BT)"
echo ""
echo "  Para compilar:"
echo "    cd $TARGET_REPO"
echo "    make -j\$(nproc) V=s 2>&1 | tee build.log"
echo ""
echo "  Imagen resultante en:"
echo "    bin/targets/bcm27xx/bcm2710/"
echo ""
