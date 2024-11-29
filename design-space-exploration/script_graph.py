import matplotlib.pyplot as plt
import numpy as np

# 1: riscv-gapbs-bfs-run
# 2: riscv-gapbs-tc-run
# 3: riscv-matrix-multiply-run
#
#

# Datos
x = ["big-1", "little-1", "big-2", "little-2", "big-3", "little-3"]
# Con 4 caches
#y1 = [00.04010, 00.05764, 00.13863, 00.19089, 00.07152, 00.14980]  # Performance
#y2 = [1.138076, 0.791657, 1.135430, 0.824583, 1.580851, 0.754818]  # IPC
#y3 = [0.7907, 0.7708, 0.7956, 0.7739, 0.7432, 0.7331]  # Hit Rate

# Con 3 caches
y1 = [00.04077, 00.05871, 00.14243, 00.19446, 00.07150, 00.14977]  # Performance
y2 = [1.119140, 0.777250, 1.105159, 0.809446, 1.581390, 0.754932]  # IPC
y3 = [0.8368, 0.8253, 0.8275, 0.8153, 0.7110, 0.6984]  # Hit Rate


# Configuración para el gráfico de barras
ancho_barras = 0.2  # Ancho de cada barra
x_indices = np.arange(len(x))  # Posiciones para las barras en el eje X

# Crear las barras
plt.bar(x_indices - ancho_barras, y1, width=ancho_barras, label="Execution time (Escala x10)", color="green")
plt.bar(x_indices, y2, width=ancho_barras, label="IPC", color="blue")
plt.bar(x_indices + ancho_barras, y3, width=ancho_barras, label="HitRate (Escala x 0,01)", color="red")

# Personalizar el gráfico
plt.title("With three level cache")
plt.xlabel("Workload")
plt.ylabel("Valores")
plt.xticks(x_indices, x)  # Etiquetas del eje X en las posiciones correctas
plt.legend()  # Muestra la leyenda
plt.grid(axis="y", linestyle="--", alpha=0.7)  # Grid en el eje Y

# Guardar el gráfico como archivo
plt.savefig("grafico_barras_con_three_level_cache.png")
print("Gráfico guardado como 'grafico_barras_varias_metricas.png'.")
