import unittest
import numpy as np
from aegis.core.telemetry import LogitEntropyMonitor
from aegis.core.moe_monitor import MoERoutingMonitor, EntanglementResult

class TestZeroDayDefense(unittest.TestCase):
    def setUp(self) -> None:
        # Configuración de monitor con límites estrictos (Producción)
        self.entropy_monitor = LogitEntropyMonitor(ema_alpha=0.1)
        self.moe_monitor = MoERoutingMonitor(
            gate_threshold=0.5, 
            activation_bound=1.5, 
            min_experts=4
        )

    def test_zero_day_latent_footprint_detection(self) -> None:
        """
        Simula un ataque Zero-Day que evade filtros de texto pero 
        provoca una anomalía en el espacio latente.
        """
        # 1. ESTADO NOMINAL
        normal_logits = np.random.randn(1000) 
        normal_gates = np.array([0.4, 0.3, 0.2, 0.1]) 
        normal_norms = np.array([1.0, 1.0, 1.0, 1.0])
        
        h_normal = self.entropy_monitor.compute_shannon_entropy(normal_logits)
        moe_normal = self.moe_monitor.detect_entanglement(normal_gates, normal_norms)
        
        self.assertFalse(moe_normal.detected, f"False positive in nominal state: {moe_normal.note}")
        print(f"\n[NOMINAL] Entropy: {h_normal:.4f}, MoE Status: {moe_normal.flag}")

        # 2. ESTADO ZERO-DAY (Simulación de Inyección Exitosa)
        # Logits colapsados: entropía mínima ( la señal más clara de inyección forzada)
        zero_day_logits = np.random.randn(1000)
        zero_day_logits[42] = 100.0 
        
        # Ruteo anómalo: Activación agregada masiva.
        # Usamos normas altas para simular la "energía" de un ataque de inyección
        # que activa múltiples rutas expertas simultáneamente.
        zero_day_gates = np.array([0.26, 0.24, 0.25, 0.25]) 
        zero_day_norms = np.array([5.0, 5.0, 5.0, 5.0]) # <--- Simulamos alta activación
        
        h_attack = self.entropy_monitor.compute_shannon_entropy(zero_day_logits)
        moe_attack = self.moe_monitor.detect_entanglement(zero_day_gates, zero_day_norms)
        
        print(f"[ATTACK] Entropy: {h_attack:.4f}, MoE Status: {moe_attack.flag}")
        print(f"[ATTACK] Note: {moe_attack.note}")

        # Verificaciones de defensa
        # A. El colapso de entropía es un indicador primario
        self.assertLess(h_attack, h_normal * 0.1)
        
        # B. El monitor MoE debe detectar el entrelazamiento
        self.assertTrue(moe_attack.detected, "Zero-Day evaded MoE Entanglement detection")
        self.assertEqual(moe_attack.flag, "ENTANGLEMENT_DETECTED")

if __name__ == "__main__":
    unittest.main(verbosity=2)
