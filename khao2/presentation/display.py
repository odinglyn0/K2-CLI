"""Display formatting and rendering."""
import os
import click
from khao2.core.models import ScanResult
from khao2.utils.formatters import format_time, format_number, create_progress_bar

BANNER = """
██╗  ██╗    ██████╗ 
██║ ██╔╝    ╚════██╗
█████╔╝      █████╔╝
██╔═██╗     ██╔═══╝ 
██║  ██╗    ███████╗
╚═╝  ╚═╝    ╚══════╝
"""


class LoadingAnimation:
    """Animated loading indicator for watch mode."""
    
    WIDTH = 20  # Character width of animation
    
    def __init__(self):
        self._position = 0
        self._direction = 1  # 1 = right, -1 = left
    
    def get_frame(self) -> str:
        """
        Get current animation frame.
        Returns string like: "[    ─────    ]" with dash moving left-to-right then right-to-left.
        """
        dash_width = 5
        frame = [' '] * self.WIDTH
        
        # Place dash at current position
        start = self._position
        end = min(start + dash_width, self.WIDTH)
        for i in range(start, end):
            frame[i] = '─'
        
        # Update position for next frame
        self._position += self._direction
        if self._position >= self.WIDTH - dash_width:
            self._direction = -1
        elif self._position <= 0:
            self._direction = 1
        
        return f"[{''.join(frame)}]"
    
    def reset(self):
        """Reset animation to start."""
        self._position = 0
        self._direction = 1


def calculate_engine_progress(completed: int, failed: int, total: int) -> dict:
    """
    Calculate accurate engine progress.
    
    Args:
        completed: Number of engines that completed successfully
        failed: Number of engines that failed
        total: Total number of engines
    
    Returns:
        dict with:
        - remaining: total - failed (engines still possible)
        - percentage: completed / remaining * 100
        - display: formatted string like "328/329"
        - failed_display: formatted string like "10 failed" or empty
    """
    remaining = total - failed
    percentage = int((completed / remaining) * 100) if remaining > 0 else 100
    return {
        'remaining': remaining,
        'percentage': percentage,
        'display': f"{completed}/{remaining}",
        'failed_display': f"{failed} failed" if failed > 0 else ""
    }


class DisplayRenderer:
    """Handles rendering of scan results to terminal."""

    @staticmethod
    def clear_screen():
        """Clear the terminal screen."""
        os.system('cls' if os.name == 'nt' else 'clear')

    @staticmethod
    def print_banner():
        """Print the application banner."""
        click.echo(click.style(BANNER, fg='cyan', bold=True))

    def display_headless_submission(self, result: ScanResult):
        """Display headless mode submission confirmation."""
        click.echo(click.style("KHAO2 IMAGE FORENSICS | Every little bit.\n", fg='cyan'))
        click.echo(click.style("ANALYSIS IN PROGRESS - HEADLESS MODE", fg='yellow', bold=True))
        click.echo(click.style("━" * 62, fg='blue'))
        click.echo()
        
        click.echo(click.style(f"STATUS: ", fg='white', bold=True) + click.style(result.status.upper(), fg='yellow'))
        click.echo(f"IMAGE ID: {result.metadata.imageid}")
        click.echo(f"USER ID: {result.metadata.userid}")
        click.echo(f"FILE SIZE: {result.metadata.filesize} bytes")
        click.echo(f"SCAN TYPE: {result.metadata.scantype}")
        click.echo(f"USER AGENT: {result.metadata.useragent}")
        click.echo(f"IP ADDRESS: {result.metadata.ipaddress}")
        click.echo(f"SUBMITTED: {result.metadata.submittedat}")
        
        click.echo(click.style("━" * 62, fg='blue'))
        click.echo()
        click.echo(f'Use "k2 get {result.metadata.imageid}" to poll for more information.')
        click.echo("This scan was submitted in headless mode, you will not receive live updates.")
        click.echo(f'If you need live updates use "k2 get {result.metadata.imageid} --watch"')

    def display_scan_status(self, result: ScanResult, animation_frame: str = None, keybind_hints: str = None):
        """Display scan status based on completion state."""
        self.clear_screen()

        if result.status == 'completed':
            self._display_completed_analysis(result)
        elif result.status == 'errored':
            self._display_errored_scan(result)
        else:
            self._display_progress(result, animation_frame, keybind_hints)

    def _display_progress(self, result: ScanResult, animation_frame: str = None, keybind_hints: str = None):
        """Display in-progress scan status."""
        # Calculate accurate engine progress: remaining = total - failed
        remaining = result.total_engines - result.failed_engines
        percentage = int((result.completed_engines / remaining) * 100) if remaining > 0 else 100
        progress_bar = create_progress_bar(result.completed_engines, remaining)

        click.echo(click.style(BANNER, fg='cyan', bold=True))
        click.echo(click.style("KHAO2 IMAGE FORENSICS | Every little bit.\n", fg='cyan'))

        # Show different header for queued status
        if result.status == 'queued':
            click.echo(click.style("SCAN QUEUED - WAITING FOR PROCESSING", fg='yellow', bold=True))
        else:
            click.echo(click.style("ANALYSIS IN PROGRESS - DO NOT TOUCH", fg='yellow', bold=True))
        click.echo(click.style("━" * 62, fg='blue'))
        click.echo()

        click.echo(click.style(f"STATUS: ", fg='white', bold=True) + click.style(result.status.upper(), fg='yellow'))
        click.echo(f"IMAGE ID: {result.metadata.imageid}")
        click.echo(f"USER ID: {result.metadata.userid}")
        click.echo(f"FILE SIZE: {result.metadata.filesize} bytes")
        click.echo(f"SCAN TYPE: {result.metadata.scantype}")
        click.echo(f"USER AGENT: {result.metadata.useragent}")
        click.echo(f"IP ADDRESS: {result.metadata.ipaddress}")
        click.echo(f"SUBMITTED: {result.metadata.submittedat}")
        click.echo()

        # Show queue information when status is "queued"
        if result.status == 'queued':
            click.echo(click.style("QUEUE STATUS", fg='cyan', bold=True))
            if result.queue_depth is not None:
                click.echo(f"├─ Position in Queue: {click.style(str(result.queue_depth), fg='yellow')}")
            if result.queued_at:
                click.echo(f"├─ Queued At: {result.queued_at}")
            if result.queue_time is not None:
                queue_time_sec = result.queue_time / 1000
                click.echo(f"└─ Estimated Wait: {click.style(f'{queue_time_sec:.1f}s', fg='yellow')}")
            click.echo()
        else:
            click.echo(click.style("PROGRESS", fg='cyan', bold=True))
            click.echo(f"├─ Completed: {click.style(str(result.completed_engines), fg='green')}/{remaining} engines")
            click.echo(f"├─ Failed: {click.style(str(result.failed_engines), fg='red' if result.failed_engines > 0 else 'white')} engines")
            click.echo(f"├─ Elapsed Time: {result.elapsed_time}ms ({format_time(result.elapsed_time)})")
            click.echo(f"└─ Used FLOPs: {result.used_flops} ({format_number(result.used_flops)})")
            click.echo()

            if percentage < 30:
                bar_color = 'red'
            elif percentage < 70:
                bar_color = 'yellow'
            else:
                bar_color = 'green'

            click.echo(click.style(f"ENGINE STATUS: ", fg='white', bold=True) +
                       click.style(f"[{progress_bar}]", fg=bar_color) +
                       click.style(f" {percentage}%", fg=bar_color, bold=True))

        click.echo(click.style("━" * 62, fg='blue'))
        click.echo()
        
        # Display loading animation if provided
        if animation_frame:
            click.echo(click.style(animation_frame, fg='cyan'))
            click.echo()
        
        # Display keybind hints if provided
        if keybind_hints:
            click.echo(click.style(keybind_hints, fg='white', dim=True))

    def _display_errored_scan(self, result: ScanResult):
        """Display errored scan status."""
        click.echo(click.style(BANNER, fg='cyan', bold=True))
        click.echo(click.style("KHAO2 IMAGE FORENSICS | Every little bit.\n", fg='cyan'))

        click.echo(click.style("🛑 SCAN FAILED", fg='red', bold=True))
        click.echo(click.style("━" * 62, fg='blue'))
        click.echo()

        click.echo(click.style(f"STATUS: ", fg='white', bold=True) + click.style("ERRORED", fg='red', bold=True))
        click.echo(f"IMAGE ID: {result.metadata.imageid}")
        click.echo(f"USER ID: {result.metadata.userid}")
        click.echo(f"FILE SIZE: {result.metadata.filesize} bytes")
        click.echo(f"SCAN TYPE: {result.metadata.scantype}")
        click.echo(f"SUBMITTED: {result.metadata.submittedat}")
        click.echo()

        click.echo(click.style("PROGRESS AT FAILURE", fg='red', bold=True))
        click.echo(f"├─ Completed: {click.style(str(result.completed_engines), fg='yellow')}/{result.total_engines} engines")
        click.echo(f"├─ Failed: {click.style(str(result.failed_engines), fg='red')} engines")
        click.echo(f"└─ Elapsed Time: {result.elapsed_time}ms ({format_time(result.elapsed_time)})")
        click.echo()

        click.echo(click.style("━" * 62, fg='blue'))
        click.echo()
        click.echo("The scan encountered an error and could not complete.")
        click.echo("Please try submitting the image again or contact support if the issue persists.")

    def _display_completed_analysis(self, result: ScanResult):
        """Display completed scan analysis."""
        if not result.static_ai:
            click.echo("Error: Incomplete scan data")
            return

        verdict = result.static_ai.verdict.upper()
        possibility = result.static_ai.possibility_of_steganography
        confidence = result.static_ai.confidence
        anomalies = result.static_ai.anomalies

        # Determine verdict color and icon
        if verdict == 'PROFILED':
            status_icon = '🛑'
            verdict_color = 'red'
        elif verdict == 'SUSPICIOUS':
            status_icon = '⚠️'
            verdict_color = 'yellow'
        else:
            status_icon = '✅'
            verdict_color = 'green'

        # Determine confidence color
        if confidence >= 80:
            confidence_color = 'red'
        elif confidence >= 50:
            confidence_color = 'yellow'
        else:
            confidence_color = 'green'

        click.echo(click.style(BANNER, fg='cyan', bold=True))
        click.echo(click.style("KHAO2 IMAGE FORENSICS | Every little bit.\n", fg='cyan'))

        click.echo(status_icon + " " + click.style("ANALYSIS COMPLETE", fg=verdict_color, bold=True))
        click.echo(click.style("━" * 62, fg='blue'))
        click.echo()

        click.echo(click.style("VERDICT: ", fg='white', bold=True) + click.style(verdict, fg=verdict_color, bold=True))
        click.echo(f"Possibility: {click.style(f'{possibility}%', fg=confidence_color, bold=True)}")
        click.echo(f"Confidence: {click.style(f'{confidence}%', fg=confidence_color, bold=True)}")
        click.echo()

        if result.file_name:
            click.echo(click.style(f"File: ", fg='white', bold=True) + result.file_name)
            if result.file_meta:
                size_pixels = f"{result.file_meta.width}x{result.file_meta.height}"
                quality = result.static_bounce.get('q', 0) if result.static_bounce else 0
                quality_str = f"{result.file_meta.format} {quality}%" if quality else result.file_meta.format
                click.echo(f"Size: {result.metadata.filesize} bytes | {size_pixels} | {quality_str}")
            click.echo()

        if result.file_hashes:
            click.echo(click.style("SSDEEP: ", fg='magenta') + click.style(result.file_hashes.ssdeep, fg='white', dim=True))
            click.echo(click.style("SHA512: ", fg='magenta') + click.style(result.file_hashes.sha512, fg='white', dim=True))
            click.echo(click.style("SHA256: ", fg='magenta') + click.style(result.file_hashes.sha256, fg='white', dim=True))
            click.echo(click.style("MD5: ", fg='magenta') + click.style(result.file_hashes.md5, fg='white', dim=True))
            click.echo()

        click.echo(click.style("ENGINES: ", fg='white', bold=True) +
                   click.style(f"{result.completed_engines}/{result.completed_engines + result.failed_engines}", fg='green') +
                   " completed | " +
                   click.style(f"{result.failed_engines}", fg='red' if result.failed_engines > 0 else 'white') + " failed")
        click.echo(f"Runtime: {result.elapsed_time}ms | {format_number(result.used_flops)} FLOPs")
        click.echo()

        if result.firm_scan:
            firm_entries = result.firm_scan.get('entries', [])
            firm_first = firm_entries[0].get('desc', 'N/A') if firm_entries else 'N/A'
            click.echo(click.style("FILE INTEGRITY", fg='cyan', bold=True))
            click.echo(f"├─ Format: {firm_first}")
            if result.file_meta:
                click.echo(f"├─ Mode: {result.file_meta.mode}")
            click.echo()

        if result.static_bounce:
            entropy = result.static_bounce.get('e', 0)
            size_score = result.static_bounce.get('s', 0)
            strings_count = result.found_strings.get('total_count', 0) if result.found_strings else 0

            click.echo(click.style("STATISTICAL ANALYSIS", fg='cyan', bold=True))
            click.echo(f"├─ Entropy: {entropy}")
            click.echo(f"├─ Size Score: {size_score}")
            click.echo(f"└─ Strings Found: {strings_count}")
            click.echo()

        anomaly_count_color = 'red' if len(anomalies) > 5 else 'yellow' if len(anomalies) > 0 else 'green'
        click.echo(click.style(f"ANOMALIES DETECTED: ", fg='white', bold=True) +
                   click.style(f"{len(anomalies)}", fg=anomaly_count_color, bold=True) +
                   f" ({click.style(f'{confidence}% CONFIDENCE', fg=confidence_color)})")

        for anomaly in anomalies:
            if anomaly.confidence >= 90:
                anom_color = 'red'
            elif anomaly.confidence >= 70:
                anom_color = 'yellow'
            else:
                anom_color = 'white'

            click.echo(click.style(f"! #{anomaly.id} ", fg=anom_color, bold=True) + anomaly.explanation)
            click.echo(f"  Confidence: {click.style(f'{anomaly.confidence}%', fg=anom_color)} | " +
                       f"Anomaly Value: {click.style(str(anomaly.anomaly_value), fg=anom_color)}")

        click.echo()
        click.echo(click.style("IDENTIFIED MEDIUM: ", fg='white', bold=True) + click.style(result.static_ai.most_possible_medium, fg='cyan'))
        click.echo(click.style("IDENTIFIED VECTOR: ", fg='white', bold=True) + result.static_ai.most_possible_vector)
        click.echo(click.style("TECHNIQUE CARDINALS: ", fg='white', bold=True) + click.style(result.static_ai.most_possible_vector_cardinals, fg='yellow'))
        
        # Display recommended next steps if available
        if result.static_ai.r_next_steps:
            click.echo()
            click.echo(click.style("RECOMMENDED NEXT STEPS: ", fg='white', bold=True))
            click.echo(click.style(f"  {result.static_ai.r_next_steps}", fg='cyan'))
        
        # Display false positive/negative reasons if available
        if result.static_ai.r_for_a_fx:
            click.echo()
            if verdict in ('PROFILED', 'SUSPICIOUS'):
                fx_label = "POTENTIAL FALSE POSITIVE REASONS:"
            else:
                fx_label = "POTENTIAL FALSE NEGATIVE REASONS:"
            click.echo(click.style(fx_label, fg='white', bold=True))
            for fx in result.static_ai.r_for_a_fx:
                likelihood_color = 'red' if fx.likelyhood >= 70 else 'yellow' if fx.likelyhood >= 40 else 'green'
                click.echo(f"  • {fx.reason} " + click.style(f"({fx.likelyhood}% likelihood)", fg=likelihood_color))
        
        click.echo(click.style("━" * 62, fg='blue'))
        click.echo()
