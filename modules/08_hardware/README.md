# 8 Dispositivos, Sensores & Hardware

Interação direta com o hardware.

## Scripts

**drm_vblank.bt**: eventos de vblank da GPU (sincronização vertical)  
**thermal_trip.bt**: eventos de temperatura térmica do sistema

## O que monitora

- Leitura de sensores
- Acesso a /dev/\*
- Temperatura
- GPU / CPU freq

## Exemplos

- hwmon
- thermal
- i2c
- ioctl em dispositivos

## Probes

- `tracepoint:syscalls:sys_enter_ioctl`
- `kprobe:dev_ioctl`
