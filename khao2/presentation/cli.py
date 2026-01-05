"""CLI interface for Khao2."""
import click
import sys
import difflib
from khao2.utils.config_manager import ConfigManager
from khao2.utils.validators import validate_token, validate_endpoint
from khao2.services.api_client import APIClient
from khao2.services.scan_service import ScanService
from khao2.services.quota_service import QuotaService
from khao2.services.account_service import AccountService
from khao2.presentation.display import DisplayRenderer, LoadingAnimation
from khao2.presentation.output_formatter import OutputFormatter
from khao2.presentation.keybinds import KeybindHandler
from khao2.core.exceptions import Khao2Error, APIError
from khao2.plugins import PluginManager, PluginContext

BANNER = """
██╗  ██╗    ██████╗ 
██║ ██╔╝    ╚════██╗
█████╔╝      █████╔╝
██╔═██╗     ██╔═══╝ 
██║  ██╗    ███████╗
╚═╝  ╚═╝    ╚══════╝
"""


def get_version():
    """Get the CLI version from package metadata."""
    try:
        from importlib.metadata import version
        return version('khao2')
    except Exception:
        return '1.0.0'


def print_banner():
    click.echo(BANNER)


# Command examples for help display
COMMAND_EXAMPLES = {
    'dig': [
        ('k2 dig ./image.png', 'Basic scan (headless)'),
        ('k2 dig ./image.jpg --watch', 'Scan with live progress'),
        ('k2 dig ./file.png --json', 'Scan with JSON output'),
    ],
    'get': [
        ('k2 get <scan_id>', 'Get scan results'),
        ('k2 get <scan_id> --watch', 'Watch scan progress'),
        ('k2 get <scan_id> --json', 'Get results as JSON'),
    ],
    'show': [
        ('k2 show <scan_id>', 'Show full scan details'),
        ('k2 show <scan_id> --json', 'Show details as JSON'),
    ],
    'list': [
        ('k2 list', 'List recent scans'),
        ('k2 list --limit 10', 'List last 10 scans'),
        ('k2 list --json', 'List scans as JSON'),
    ],
    'abort': [
        ('k2 abort <scan_id>', 'Abort a running scan'),
    ],
    'delete': [
        ('k2 delete <scan_id>', 'Delete a completed scan'),
        ('k2 delete <scan_id> --force', 'Delete without confirmation'),
    ],
    'quota': [
        ('k2 quota', 'Check remaining credits'),
        ('k2 quota --json', 'Get quota as JSON'),
    ],
    'usage': [
        ('k2 usage', 'Show current month usage'),
        ('k2 usage --start 2024-01-01', 'Show usage from date'),
        ('k2 usage --json', 'Get usage as JSON'),
    ],
    'audit': [
        ('k2 audit', 'Show audit logs'),
        ('k2 audit --limit 20', 'Show last 20 audit entries'),
    ],
    'batch': [
        ('k2 batch image1.png image2.jpg', 'Process multiple images'),
        ('k2 batch ./images --recursive', 'Scan directory recursively'),
        ('k2 batch ./files --pattern "*.png"', 'Custom file pattern'),
    ],
    'report': [
        ('k2 report dashboard.html', 'Generate HTML dashboard'),
        ('k2 report analysis.pdf --format pdf', 'Export as PDF'),
        ('k2 report summary.html --executive', 'Executive summary report'),
    ],
    'plugins': [
        ('k2 plugins list', 'List available plugins'),
        ('k2 plugins load batch_processor', 'Load a plugin'),
    ],
    'token': [
        ('k2 token set <token>', 'Set API token'),
    ],
    'endpoint': [
        ('k2 endpoint set <url>', 'Set API endpoint'),
    ],
}


class CustomGroup(click.Group):
    """Custom Click group with enhanced help formatting and typo suggestions."""

    def format_help(self, ctx, formatter):
        """Override to add banner and examples to help output."""
        # Add banner
        formatter.write(BANNER)
        formatter.write(f"Khao2 CLI v{get_version()} - Advanced stegananalysis platform\n\n")
        
        # Write usage
        self.format_usage(ctx, formatter)
        formatter.write_paragraph()
        
        # Write help text
        self.format_help_text(ctx, formatter)
        
        # Write commands
        self.format_commands(ctx, formatter)
        
        # Add examples section
        formatter.write_paragraph()
        formatter.write("Examples:\n")
        examples = [
            ('k2 dig ./image.png --watch', 'Scan image and watch progress'),
            ('k2 batch ./images --recursive', 'Batch process directory'),
            ('k2 report dashboard.html', 'Generate analysis report'),
            ('k2 plugins list', 'List available plugins'),
            ('k2 list --limit 10', 'List last 10 scans'),
            ('k2 quota', 'Check remaining credits'),
        ]
        for cmd, desc in examples:
            formatter.write(f"  {cmd:<30} {desc}\n")
        
        formatter.write_paragraph()
        formatter.write("Run 'k2 help <command>' for detailed command usage.\n")
        
        # Write only the options (not commands again)
        formatter.write_paragraph()
        formatter.write("Options:\n")
        for param in self.get_params(ctx):
            rv = param.get_help_record(ctx)
            if rv is not None:
                formatter.write(f"  {rv[0]:<20} {rv[1]}\n")

    def format_commands(self, ctx, formatter):
        """Format the commands section."""
        commands = []
        for subcommand in self.list_commands(ctx):
            cmd = self.get_command(ctx, subcommand)
            if cmd is None:
                continue
            help_text = cmd.get_short_help_str(limit=50)
            commands.append((subcommand, help_text))

        if commands:
            formatter.write_paragraph()
            formatter.write("Commands:\n")
            max_len = max(len(cmd[0]) for cmd in commands)
            for subcommand, help_text in commands:
                formatter.write(f"  {subcommand:<{max_len + 2}} {help_text}\n")

    def get_command(self, ctx, cmd_name):
        """Override to suggest similar commands on typo."""
        rv = click.Group.get_command(self, ctx, cmd_name)
        if rv is not None:
            return rv
        
        # Command not found - suggest similar commands
        matches = difflib.get_close_matches(
            cmd_name, 
            self.list_commands(ctx), 
            n=3, 
            cutoff=0.6
        )
        
        if matches:
            ctx.fail(f"Unknown command '{cmd_name}'. Did you mean: {', '.join(matches)}?")
        
        return None

    def resolve_command(self, ctx, args):
        """Override to handle unknown commands gracefully."""
        try:
            return super().resolve_command(ctx, args)
        except click.UsageError:
            # Re-raise to let get_command handle suggestions
            raise


class CustomCommand(click.Command):
    """Custom Click command with enhanced help formatting."""

    def format_help(self, ctx, formatter):
        """Override to add examples to command help."""
        # Write usage
        self.format_usage(ctx, formatter)
        formatter.write_paragraph()
        
        # Write help text
        self.format_help_text(ctx, formatter)
        
        # Write options
        self.format_options(ctx, formatter)
        
        # Add examples if available
        cmd_name = ctx.info_name
        if cmd_name in COMMAND_EXAMPLES:
            formatter.write_paragraph()
            formatter.write("Examples:\n")
            for cmd, desc in COMMAND_EXAMPLES[cmd_name]:
                formatter.write(f"  {cmd:<35} {desc}\n")
        
        # Add watch mode keybinds for dig and get commands
        if cmd_name in ['dig', 'get']:
            formatter.write_paragraph()
            formatter.write("Watch Mode Keybinds:\n")
            formatter.write("  K+A      Abort scan on server and exit\n")
            formatter.write("  K+B      Exit client (scan continues)\n")
            formatter.write("  Ctrl+C   Hard abort (server + client)\n")


@click.group(cls=CustomGroup)
@click.version_option(version=get_version(), prog_name='k2')
def cli():
    """Khao2 - Advanced stegananalysis platform."""
    pass


@cli.group()
def token():
    """Manage API token configuration."""
    pass


@token.command('set')
@click.argument('token_value')
def set_token(token_value):
    """Set the API token."""
    try:
        validate_token(token_value)
        config_manager = ConfigManager()
        config_manager.save(token=token_value)
        print_banner()
        click.echo("Token configured successfully.")
    except Khao2Error as e:
        print_banner()
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


@cli.group()
def endpoint():
    """Manage API endpoint configuration."""
    pass


@endpoint.command('set')
@click.argument('endpoint_url')
def set_endpoint(endpoint_url):
    """Set the API endpoint URL."""
    try:
        validate_endpoint(endpoint_url)
        config_manager = ConfigManager()
        config_manager.save(endpoint=endpoint_url)
        print_banner()
        click.echo("Endpoint configured successfully.")
    except Khao2Error as e:
        print_banner()
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


@cli.group()
def plugins():
    """Manage plugins."""
    pass


@plugins.command('list')
@click.option('--available', is_flag=True, help='List available plugins')
@click.option('--loaded', is_flag=True, help='List loaded plugins')
def list_plugins(available, loaded):
    """List plugins."""
    try:
        config_manager = ConfigManager()
        config = config_manager.load()

        api_client = APIClient(config['endpoint'], config['token'])
        scan_service = ScanService(api_client)
        quota_service = QuotaService(api_client)
        account_service = AccountService(api_client)

        plugin_manager = PluginManager()
        plugin_context = PluginContext(
            config=config,
            services={
                'api_client': api_client,
                'scan_service': scan_service,
                'quota_service': quota_service,
                'account_service': account_service,
            }
        )

        if available or not loaded:
            print_banner()
            click.echo("Available Plugins:")
            click.echo("━" * 50)

            available_plugins = plugin_manager.discover_plugins()
            if available_plugins:
                for name, metadata in available_plugins.items():
                    click.echo(f"  {name:<20} {metadata.description}")
                    click.echo(f"    Type: {metadata.plugin_type}, Version: {metadata.version}")
                    click.echo()
            else:
                click.echo("  No plugins found.")
        else:
            print_banner()
            click.echo("Loaded Plugins:")
            click.echo("━" * 50)

            loaded_plugins = plugin_manager.list_loaded_plugins()
            if loaded_plugins:
                for name in loaded_plugins:
                    click.echo(f"  {name}")
            else:
                click.echo("  No plugins loaded.")

    except Khao2Error as e:
        print_banner()
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


@plugins.command('load')
@click.argument('plugin_name')
def load_plugin(plugin_name):
    """Load a plugin."""
    try:
        config_manager = ConfigManager()
        config = config_manager.load()

        api_client = APIClient(config['endpoint'], config['token'])
        scan_service = ScanService(api_client)
        quota_service = QuotaService(api_client)
        account_service = AccountService(api_client)

        plugin_manager = PluginManager()
        plugin_context = PluginContext(
            config=config,
            services={
                'api_client': api_client,
                'scan_service': scan_service,
                'quota_service': quota_service,
                'account_service': account_service,
            }
        )

        plugin = plugin_manager.load_plugin(plugin_name, plugin_context)
        print_banner()
        click.echo(f"Plugin '{plugin_name}' loaded successfully.")
        click.echo(f"Description: {plugin.metadata.description}")

    except Khao2Error as e:
        print_banner()
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


@plugins.command('unload')
@click.argument('plugin_name')
def unload_plugin(plugin_name):
    """Unload a plugin."""
    try:
        plugin_manager = PluginManager()
        plugin_manager.unload_plugin(plugin_name)
        print_banner()
        click.echo(f"Plugin '{plugin_name}' unloaded successfully.")
    except Khao2Error as e:
        print_banner()
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


@cli.command(cls=CustomCommand)
@click.argument('image_path')
@click.option('--watch', is_flag=True, help='Watch scan progress in real-time')
@click.option('--debug', is_flag=True, help='Show debug information')
@click.option('--json', 'json_output', is_flag=True, help='Output results in JSON format')
@click.option('--skip-quota-check', is_flag=True, help='Skip pre-scan quota check')
def dig(image_path, watch, debug, json_output, skip_quota_check):
    """Upload and scan an image."""
    config_manager = ConfigManager()
    config = config_manager.load()

    if debug:
        click.echo(f"[DEBUG] Configured endpoint: {config['endpoint']}")
        click.echo(f"[DEBUG] Token configured: {'Yes' if config['token'] else 'No'}")
        click.echo(f"[DEBUG] Token: {config['token']}")

    if not json_output:
        print_banner()

    try:
        api_client = APIClient(config['endpoint'], config['token'], debug=debug)
        scan_service = ScanService(api_client)
        quota_service = QuotaService(api_client)
        display_renderer = DisplayRenderer()
        formatter = OutputFormatter(json_mode=json_output)

        # Pre-scan quota check
        if not skip_quota_check:
            can_scan, message = quota_service.check_can_scan()
            if not can_scan:
                click.echo(f"Error: {message}", err=True)
                sys.exit(1)
            if message:  # Warning message for low credits
                click.echo(click.style(message, fg='yellow'), err=True)

        scan_id = scan_service.upload_and_scan(image_path)

        if watch:
            # Use enhanced polling with keybinds and animation
            keybind_handler = KeybindHandler(scan_id, api_client, is_dig_mode=True)
            loading_animation = LoadingAnimation()
            
            scan_service.poll_scan_status_with_keybinds(
                scan_id,
                callback=display_renderer.display_scan_status,
                keybind_handler=keybind_handler,
                loading_animation=loading_animation
            )
        else:
            # Headless mode - get initial status and display
            result = scan_service.get_scan_result(scan_id)
            if json_output:
                click.echo(formatter.format_scan_result(result))
            else:
                display_renderer.display_headless_submission(result)
    except Khao2Error as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


@cli.command(cls=CustomCommand)
@click.argument('paths', nargs=-1, required=True)
@click.option('--recursive', '-r', is_flag=True, help='Recursively scan directories')
@click.option('--pattern', default='*.png;*.jpg;*.jpeg;*.gif;*.bmp;*.webp', help='File pattern to match')
@click.option('--json', 'json_output', is_flag=True, help='Output results in JSON format')
@click.option('--output', '-o', 'output_file', help='Save results to file')
def batch(paths, recursive, pattern, json_output, output_file):
    """Process multiple images in batch."""
    from pathlib import Path
    from khao2.plugins import PluginManager, PluginContext

    config_manager = ConfigManager()
    config = config_manager.load()

    if not json_output:
        print_banner()

    try:
        api_client = APIClient(config['endpoint'], config['token'])
        scan_service = ScanService(api_client)
        quota_service = QuotaService(api_client)
        account_service = AccountService(api_client)

        plugin_manager = PluginManager()
        plugin_context = PluginContext(
            config=config,
            services={
                'api_client': api_client,
                'scan_service': scan_service,
                'quota_service': quota_service,
                'account_service': account_service,
            }
        )

        # Load batch processor plugin
        batch_plugin = plugin_manager.load_plugin('batch_processor', plugin_context)

        # Collect all files to process
        import glob
        all_files = []
        for path_str in paths:
            path = Path(path_str)
            if path.is_file():
                all_files.append(path)
            elif path.is_dir():
                if recursive:
                    # Use glob for recursive matching
                    pattern_parts = pattern.split(',')
                    for part in pattern_parts:
                        glob_pattern = f"**/{part.strip()}"
                        all_files.extend(path.glob(glob_pattern))
                else:
                    # Non-recursive directory scan
                    pattern_parts = pattern.split(',')
                    for part in pattern_parts:
                        glob_pattern = part.strip()
                        all_files.extend(path.glob(glob_pattern))

        if not all_files:
            click.echo("No files found matching the specified pattern.", err=True)
            sys.exit(1)

        # Remove duplicates
        all_files = list(set(all_files))

        click.echo(f"Found {len(all_files)} files to process")

        # Process batch
        results = batch_plugin.process(all_files)

        # Display results
        successful = sum(1 for r in results if not r.get('error'))
        failed = len(results) - successful

        if json_output:
            import json
            output_data = {
                "total_files": len(all_files),
                "successful": successful,
                "failed": failed,
                "results": results
            }
            if output_file:
                with open(output_file, 'w') as f:
                    json.dump(output_data, f, indent=2)
                click.echo(f"Results saved to {output_file}")
            else:
                click.echo(json.dumps(output_data, indent=2))
        else:
            click.echo(f"\nBatch processing complete:")
            click.echo(f"  Total files: {len(all_files)}")
            click.echo(f"  Successful: {successful}")
            click.echo(f"  Failed: {failed}")

            if failed > 0:
                click.echo(f"\nFailed files:")
                for result in results:
                    if result.get('error'):
                        click.echo(f"  - {result.get('item', 'unknown')}: {result['error']}")

            if output_file:
                import json
                with open(output_file, 'w') as f:
                    json.dump({
                        "total_files": len(all_files),
                        "successful": successful,
                        "failed": failed,
                        "results": results
                    }, f, indent=2)
                click.echo(f"\nDetailed results saved to {output_file}")

    except Khao2Error as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


@cli.command(cls=CustomCommand)
@click.argument('imageid')
@click.option('--watch', is_flag=True, help='Watch scan progress in real-time')
@click.option('--debug', is_flag=True, help='Show debug information')
@click.option('--json', 'json_output', is_flag=True, help='Output results in JSON format')
def get(imageid, watch, debug, json_output):
    """Get scan results by image ID."""
    config_manager = ConfigManager()
    config = config_manager.load()

    if debug:
        click.echo(f"[DEBUG] Configured endpoint: {config['endpoint']}")
        click.echo(f"[DEBUG] Token configured: {'Yes' if config['token'] else 'No'}")
        click.echo("")

    if not json_output:
        print_banner()

    try:
        api_client = APIClient(config['endpoint'], config['token'], debug=debug)
        scan_service = ScanService(api_client)
        display_renderer = DisplayRenderer()
        formatter = OutputFormatter(json_mode=json_output)

        if watch:
            # Use enhanced polling with keybinds and animation
            # is_dig_mode=False means Ctrl+C won't abort the server-side scan
            keybind_handler = KeybindHandler(imageid, api_client, is_dig_mode=False)
            loading_animation = LoadingAnimation()
            
            result = scan_service.poll_scan_status_with_keybinds(
                imageid,
                callback=display_renderer.display_scan_status,
                keybind_handler=keybind_handler,
                loading_animation=loading_animation
            )
            
            # If we got a result and json output is requested, print it
            if result and json_output:
                click.echo(formatter.format_scan_result(result))
        else:
            result = scan_service.get_scan_result(imageid)
            if json_output:
                click.echo(formatter.format_scan_result(result))
            else:
                display_renderer.display_scan_status(result)
    except Khao2Error as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


@cli.command(cls=CustomCommand)
@click.option('--json', 'json_output', is_flag=True, help='Output in JSON format')
def quota(json_output):
    """Display quota information."""
    config_manager = ConfigManager()
    config = config_manager.load()

    if not json_output:
        print_banner()

    try:
        api_client = APIClient(config['endpoint'], config['token'])
        quota_service = QuotaService(api_client)
        formatter = OutputFormatter(json_mode=json_output)

        quota_info = quota_service.get_quota()
        click.echo(formatter.format_quota(quota_info))
    except Khao2Error as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


@cli.command('list', cls=CustomCommand)
@click.option('--limit', default=50, type=int, help='Maximum number of results (max 100)')
@click.option('--offset', default=0, type=int, help='Number of results to skip')
@click.option('--json', 'json_output', is_flag=True, help='Output in JSON format')
def list_scans(limit, offset, json_output):
    """List previous scans."""
    config_manager = ConfigManager()
    config = config_manager.load()

    if not json_output:
        print_banner()

    try:
        api_client = APIClient(config['endpoint'], config['token'])
        scan_service = ScanService(api_client)
        formatter = OutputFormatter(json_mode=json_output)

        scan_list = scan_service.list_scans(limit=min(limit, 100), offset=offset)
        click.echo(formatter.format_scan_list(scan_list))
    except Khao2Error as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


@cli.command(cls=CustomCommand)
@click.argument('output_path', type=click.Path())
@click.option('--format', 'output_format', default='html', type=click.Choice(['html', 'json', 'csv', 'pdf']), help='Output format')
@click.option('--days', default=30, type=int, help='Number of days to include in report')
@click.option('--template', default='default', help='Report template to use')
@click.option('--executive', is_flag=True, help='Generate executive summary report')
def report(output_path, output_format, days, template, executive):
    """Generate comprehensive analysis reports."""
    from pathlib import Path
    from khao2.plugins import PluginManager, PluginContext

    config_manager = ConfigManager()
    config = config_manager.load()

    print_banner()

    try:
        api_client = APIClient(config['endpoint'], config['token'])
        scan_service = ScanService(api_client)
        quota_service = QuotaService(api_client)
        account_service = AccountService(api_client)

        plugin_manager = PluginManager()
        plugin_context = PluginContext(
            config=config,
            services={
                'api_client': api_client,
                'scan_service': scan_service,
                'quota_service': quota_service,
                'account_service': account_service,
            }
        )

        # Load reporting plugin
        reporting_plugin = plugin_manager.load_plugin('reporting_visualization', plugin_context)

        # Generate report data
        if executive:
            report_data = reporting_plugin.generate_executive_report(days=days)
        else:
            report_data = reporting_plugin.generate_dashboard_data(days=days)

        # Export report
        reporting_plugin.export(report_data, Path(output_path), format=output_format, template=template)

        click.echo(f"Report generated successfully: {output_path}")

    except Khao2Error as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


@cli.command(cls=CustomCommand)
@click.argument('scan_id')
def abort(scan_id):
    """Abort a running scan."""
    config_manager = ConfigManager()
    config = config_manager.load()

    print_banner()

    try:
        api_client = APIClient(config['endpoint'], config['token'])
        scan_service = ScanService(api_client)

        success = scan_service.abort_scan(scan_id)
        if success:
            click.echo(f"Scan {scan_id} abort request sent successfully.")
        else:
            click.echo(f"Failed to abort scan {scan_id}.", err=True)
            sys.exit(1)
    except APIError as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)
    except Khao2Error as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


@cli.command(cls=CustomCommand)
@click.argument('scan_id')
@click.option('--force', is_flag=True, help='Skip confirmation prompt')
def delete(scan_id, force):
    """Delete a completed scan."""
    config_manager = ConfigManager()
    config = config_manager.load()

    print_banner()

    if not force:
        if not click.confirm(f"Are you sure you want to delete scan {scan_id}?"):
            click.echo("Delete cancelled.")
            return

    try:
        api_client = APIClient(config['endpoint'], config['token'])
        scan_service = ScanService(api_client)

        success = scan_service.delete_scan(scan_id)
        if success:
            click.echo(f"Scan {scan_id} deleted successfully.")
        else:
            click.echo(f"Failed to delete scan {scan_id}.", err=True)
            sys.exit(1)
    except APIError as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)
    except Khao2Error as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


@cli.command(cls=CustomCommand)
@click.option('--start', type=str, help='Start date filter (YYYY-MM-DD)')
@click.option('--end', type=str, help='End date filter (YYYY-MM-DD)')
@click.option('--json', 'json_output', is_flag=True, help='Output in JSON format')
def usage(start, end, json_output):
    """Display usage analytics."""
    config_manager = ConfigManager()
    config = config_manager.load()

    if not json_output:
        print_banner()

    try:
        api_client = APIClient(config['endpoint'], config['token'])
        account_service = AccountService(api_client)
        formatter = OutputFormatter(json_mode=json_output)

        usage_data = account_service.get_usage(start=start, end=end)
        click.echo(formatter.format_usage(usage_data))
    except Khao2Error as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


@cli.command(cls=CustomCommand)
@click.option('--limit', default=50, type=int, help='Maximum number of results')
@click.option('--json', 'json_output', is_flag=True, help='Output in JSON format')
def audit(limit, json_output):
    """Display audit logs."""
    config_manager = ConfigManager()
    config = config_manager.load()

    if not json_output:
        print_banner()

    try:
        api_client = APIClient(config['endpoint'], config['token'])
        account_service = AccountService(api_client)
        formatter = OutputFormatter(json_mode=json_output)

        audit_logs = account_service.get_audit_logs(limit=limit)
        click.echo(formatter.format_audit_logs(audit_logs))
    except Khao2Error as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


@cli.command(cls=CustomCommand)
@click.argument('scan_id')
@click.option('--json', 'json_output', is_flag=True, help='Output in JSON format')
def show(scan_id, json_output):
    """Show full scan details."""
    config_manager = ConfigManager()
    config = config_manager.load()

    if not json_output:
        print_banner()

    try:
        api_client = APIClient(config['endpoint'], config['token'])
        scan_service = ScanService(api_client)
        formatter = OutputFormatter(json_mode=json_output)

        result = scan_service.get_scan_result(scan_id)
        
        # If scan is not completed, suggest using --watch
        if result.status not in ['completed', 'failed', 'error']:
            if not json_output:
                click.echo(f"Scan is currently {result.status}. Use 'k2 get {scan_id} --watch' to monitor progress.\n")
        
        click.echo(formatter.format_scan_result(result))
    except Khao2Error as e:
        click.echo(f"Error: {str(e)}", err=True)
        sys.exit(1)


@cli.command('help')
@click.argument('command_name', required=False)
@click.pass_context
def help_command(ctx, command_name):
    """Show help for a command."""
    if command_name:
        # Get the specific command
        cmd = cli.get_command(ctx, command_name)
        if cmd:
            # Create a new context for the command
            with ctx.scope() as sub_ctx:
                sub_ctx = click.Context(cmd, info_name=command_name, parent=ctx)
                click.echo(cmd.get_help(sub_ctx))
        else:
            # get_command will have already printed the suggestion
            pass
    else:
        # Show main help
        click.echo(ctx.parent.get_help() if ctx.parent else cli.get_help(ctx))


if __name__ == '__main__':
    cli()
