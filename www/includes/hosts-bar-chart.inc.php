<script>
// Données
var barChartData = {
    datasets: [{
        data: [<?=$datas?>],
        backgroundColor: [<?=$backgrounds?>],
        borderWidth: 0.4,
        barThickness: 20,
    }],
    labels: [<?=$labels?>],
};
// Options
var barChartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
        legend: {
            display: false
        },
        title: {
            display: true,
            text: "<?=$title?>"
        }
    },
    elements: {
        point: {
            radius: 0
        }
    },
    indexAxis: 'y',
    scales: {
        y: {
            beginAtZero: true,
            
        },
        x: {
            ticks: {
                stepSize: 1
            }
        }
    }
}
// Affichage du chart
var ctx = document.getElementById('<?=$chartId?>').getContext("2d");
window.myBar = new Chart(ctx, {
    type: "bar",
    data: barChartData,
    options: barChartOptions
});
</script>