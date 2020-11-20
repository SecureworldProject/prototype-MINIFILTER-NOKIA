# prototype-MINIFILTER-NOKIA
Repositorio del prototipo Minifilter del proyecto SECUREWORLD.

## Manual de uso

#### Instalación

Para instalar el minifilter basta con hacer clic secundario en el archivo .inf asociado y seleccionar la opción de instalar. Se pedirá confirmación de UAC para proceder con la instalación ya que requiere permisos de administrador.

Hecho esto el minifilter queda instalado, y no se requiere repetir este paso nunca más (ni siquiera tras reiniciar la máquina).


#### Arranque

Después de instalarlo habría que activarlo. Para ello, es necesario abrir una ventana de comandos con permisos de administrador y ejecutar el siguiente comando:
> net start <NOMBRE_SERVICIO_MINIFILTER>

En este caso sería:
> net start fsfilter1
