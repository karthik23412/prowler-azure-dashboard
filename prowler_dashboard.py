import pandas as pd
import plotly.express as px
import plotly.graph_objs as go
from dash import Dash, dcc, html, Input, Output
from datetime import datetime
import random

# Sample data (enhanced with dummy timestamps)
statuses = ["FAIL"] * 20 + ["PASS"]
severities = [
    "medium", "high", "low", "medium", "medium", "high", "high", "high",
    "high", "high", "high", "high", "high", "high", "high", "medium",
    "medium", "high", "medium", "medium", "high"
]
services = [
    "network", "iam", "appinsights", "monitor", "monitor", "monitor",
    "monitor", "monitor", "monitor", "monitor", "monitor", "monitor",
    "monitor", "monitor", "monitor", "defender", "defender", "defender",
    "network", "iam", "iam"
]
checks = [
    "network_bastion_host_exists", "iam_custom_role_has_permissions_to_administer_resource_locks",
    "appinsights_ensure_is_configured", "monitor_diagnostic_setting_with_appropriate_categories",
    "monitor_diagnostic_settings_exists", "monitor_alert_create_update_nsg",
    "monitor_alert_create_update_public_ip_address_rule", "monitor_alert_create_update_security_solution",
    "monitor_alert_create_update_sqlserver_fr", "monitor_alert_create_policy_assignment",
    "monitor_alert_delete_nsg", "monitor_alert_delete_policy_assignment",
    "monitor_alert_delete_public_ip_address_rule", "monitor_alert_delete_security_solution",
    "monitor_alert_delete_sqlserver_fr", "defender_ensure_mcas_is_enabled",
    "defender_ensure_wdatp_is_enabled", "defender_ensure_iot_hub_defender_is_on",
    "network_watcher_enabled", "iam_subscription_roles_owner_custom_not_created", "iam_test"
]

# Generate timestamps
now = datetime.now()
timestamps = [now.replace(minute=(now.minute - i) % 60) for i in range(len(checks))]

df = pd.DataFrame({
    "Status": statuses,
    "Severity": severities,
    "Service Name": services,
    "Check ID": checks,
    "Timestamp": timestamps
})

# Custom severity colors
severity_colors = {
    "high": "#FF4C4C",   # Red
    "medium": "#FFA500", # Orange
    "low": "#32CD32"     # Green
}

app = Dash(__name__)
app.title = "🚨 Azure Security Dashboard - Prowler"

app.layout = html.Div(style={"backgroundColor": "#111111", "color": "#FFFFFF", "padding": "20px"}, children=[

    html.H1("🚀 Azure Security Dashboard (Prowler)", style={"textAlign": "center", "color": "#00CED1"}),

    html.Div(id="kpi-cards", style={"display": "flex", "justifyContent": "space-around", "marginTop": "20px"}),

    html.Div([
        html.Label("🎯 Filter by Severity", style={"marginTop": "20px"}),
        dcc.Dropdown(
            options=[{"label": sev.title(), "value": sev} for sev in df["Severity"].unique()],
            value=None,
            id="severity-filter",
            placeholder="Select severity",
            style={"width": "50%", "marginBottom": "20px", "color": "#000000"}
        ),
        html.Button("🔄 Refresh Now", id="refresh-button", n_clicks=0, style={"marginLeft": "20px"}),
    ], style={"textAlign": "center"}),

    dcc.Interval(id="auto-refresh", interval=60000, n_intervals=0),  # Auto-refresh every 60 sec

    dcc.Graph(id="bar-status"),
    dcc.Graph(id="pie-severity"),
    dcc.Graph(id="bar-service"),
    dcc.Graph(id="timeline-graph"),
    dcc.Graph(id="heatmap"),

    html.Div("🔒 Made with ❤️ using Dash, Plotly, and Python", style={"textAlign": "center", "paddingTop": "40px", "color": "#777"})
])

@app.callback(
    Output("kpi-cards", "children"),
    Input("refresh-button", "n_clicks")
)
def update_kpis(_):
    return [
        html.Div([
            html.H3("Total Checks", style={"textAlign": "center"}),
            html.H4(f"{len(df)}", style={"textAlign": "center", "color": "#FFD700"})
        ], className="card"),
        html.Div([
            html.H3("Total Fails", style={"textAlign": "center"}),
            html.H4(f"{len(df[df['Status'] == 'FAIL'])}", style={"textAlign": "center", "color": "#FF6347"})
        ], className="card"),
        html.Div([
            html.H3("Total Passes", style={"textAlign": "center"}),
            html.H4(f"{len(df[df['Status'] == 'PASS'])}", style={"textAlign": "center", "color": "#32CD32"})
        ], className="card")
    ]

@app.callback(
    [Output("bar-status", "figure"),
     Output("pie-severity", "figure"),
     Output("bar-service", "figure"),
     Output("timeline-graph", "figure"),
     Output("heatmap", "figure")],
    [Input("severity-filter", "value"),
     Input("refresh-button", "n_clicks"),
     Input("auto-refresh", "n_intervals")]
)
def update_graphs(selected_severity, _, __):
    dff = df[df["Severity"] == selected_severity] if selected_severity else df

    fig_status = px.histogram(
        dff, x="Status", color="Severity", title="Check Status Distribution",
        color_discrete_map=severity_colors, template="plotly_dark", barmode="group"
    )

    fig_pie = px.pie(
        dff, names="Severity", title="Severity Distribution", hole=0.4,
        color="Severity", color_discrete_map=severity_colors, template="plotly_dark"
    )

    fig_service = px.histogram(
        dff, x="Service Name", color="Severity", title="Service-Wise Findings",
        color_discrete_map=severity_colors, template="plotly_dark", barmode="stack"
    )

    fig_timeline = px.scatter(
        dff, x="Timestamp", y="Service Name", color="Severity", title="🕒 Timeline of Findings",
        color_discrete_map=severity_colors, template="plotly_dark", size_max=10
    )

    heat_data = dff.groupby(["Service Name", "Severity"]).size().reset_index(name="Count")
    fig_heatmap = px.density_heatmap(
        heat_data, x="Severity", y="Service Name", z="Count", color_continuous_scale="OrRd",
        title="🔥 Heatmap: Service vs Severity", template="plotly_dark"
    )

    return fig_status, fig_pie, fig_service, fig_timeline, fig_heatmap

if __name__ == '__main__':
    app.run_server(debug=True, port=8050)
