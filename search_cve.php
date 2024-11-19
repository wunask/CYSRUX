<?php
session_start();

// Set language based on session or default to English
$lang = isset($_SESSION['lang']) ? $_SESSION['lang'] : 'en';

// Check if the language is changed via GET parameter and update session
if (isset($_GET['lang']) && in_array($_GET['lang'], ['en', 'ar'])) {
    $lang = $_GET['lang'];
    $_SESSION['lang'] = $lang;
}

// Translation mappings for English and Arabic
$translations = [
    'en' => [
        'title' => 'CVE Search',
        'search_placeholder' => 'Enter CVE ID (e.g., CVE-2021-34527)',
        'search_button' => 'Search',
        'loading' => 'Loading...',
        'invalid_format' => 'Invalid CVE ID format. Please use CVE-YYYY-NNNN format.',
        'details_for' => 'Details for',
        'no_data' => 'No data found for CVE ID:',
        'error' => 'Error retrieving data. Please try again later.',
        'id' => 'ID',
        'description' => 'Description',
        'published_date' => 'Published Date',
        'last_modified' => 'Last Modified',
        'references' => 'References'
    ],
    'ar' => [
        'title' => 'بحث عن الثغرات',
        'search_placeholder' => 'أدخل CVE ID (مثال، CVE-2021-34527)',
        'search_button' => 'بحث',
        'loading' => 'جارٍ التحميل...',
        'invalid_format' => 'تنسيق CVE ID غير صالح. يرجى استخدام التنسيق CVE-YYYY-NNNN.',
        'details_for' => 'التفاصيل لـ',
        'no_data' => 'لم يتم العثور على بيانات لـ CVE ID:',
        'error' => 'خطأ في استرجاع البيانات. يرجى المحاولة لاحقًا.',
        'id' => 'المعرف',
        'description' => 'الوصف',
        'published_date' => 'تاريخ النشر',
        'last_modified' => 'آخر تعديل',
        'references' => 'المراجع'
    ]
];

// Use the selected language translations
$text = $translations[$lang];

// Define search result variables
$searchResult = '';
$cveData = [];

// CVE Search functionality
if (isset($_POST['search'])) {
    $cveId = htmlspecialchars(trim($_POST['cve_id']));

    // Validate the CVE ID format
    if (preg_match('/^CVE-\d{4}-\d{4,}$/', $cveId)) {
        // Call the CVE Search API
        $apiUrl = "https://cve.circl.lu/api/cve/$cveId";
        $response = @file_get_contents($apiUrl);

        // Check if the API call was successful
        if ($response !== false) {
            $cveData = json_decode($response, true);
            if (isset($cveData['id'])) {
                $searchResult = $text['details_for'] . " <strong>$cveId</strong>:";
            } else {
                $searchResult = $text['no_data'] . " <strong>$cveId</strong>.";
            }
        } else {
            $searchResult = $text['error'];
        }
    } else {
        $searchResult = $text['invalid_format'];
    }
}
?>

<!DOCTYPE html>
<html lang="<?php echo $lang; ?>" dir="<?php echo $lang === 'ar' ? 'rtl' : 'ltr'; ?>">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><?php echo $text['title']; ?></title>
    <script>
        document.addEventListener('DOMContentLoaded', () => {
            const searchForm = document.querySelector('form');
            const cveInput = document.querySelector('input[name="cve_id"]');
            const resultDiv = document.querySelector('.result');

            // Prevent form submission if the CVE ID format is invalid
            searchForm.addEventListener('submit', (event) => {
                const cveId = cveInput.value.trim();
                const validFormat = /^CVE-\d{4}-\d{4,}$/.test(cveId);

                if (!validFormat) {
                    event.preventDefault();
                    alert('<?php echo $text['invalid_format']; ?>');
                }
            });

            // Display a loading animation while searching
            searchForm.addEventListener('submit', () => {
                resultDiv.innerHTML = '<p><?php echo $text['loading']; ?></p>';
            });
        });
    </script>
</head>
<body>

    <div class="container">
        <!-- Language Toggle Links -->

        <h1><?php echo $text['title']; ?></h1>
        <form method="POST" action="">
            <input type="text" name="cve_id" placeholder="<?php echo $text['search_placeholder']; ?>" required>
            <button type="submit" name="search"><?php echo $text['search_button']; ?></button>
        </form>

        <div class="result">
            <?php if ($searchResult): ?>
                <h3><?php echo $searchResult; ?></h3>
                <?php if (!empty($cveData)): ?>
                    <p><strong><?php echo $text['id']; ?>:</strong> <?php echo htmlspecialchars($cveData['id']); ?></p>
                    <p><strong><?php echo $text['description']; ?>:</strong> <?php echo htmlspecialchars($cveData['summary']); ?></p>
                    <p><strong><?php echo $text['published_date']; ?>:</strong> <?php echo htmlspecialchars($cveData['Published']); ?></p>
                    <p><strong><?php echo $text['last_modified']; ?>:</strong> <?php echo htmlspecialchars($cveData['Modified']); ?></p>
                    <div class="reference">
                        <strong><?php echo $text['references']; ?>:</strong>
                        <ul>
                            <?php foreach ($cveData['references'] as $reference): ?>
                                <li><a href="<?php echo htmlspecialchars($reference); ?>" target="_blank">
                                    <?php echo htmlspecialchars($reference); ?>
                                </a></li>
                            <?php endforeach; ?>
                        </ul>
                    </div>
                <?php endif; ?>
            <?php endif; ?>
        </div>

    </div>

</body>
</html>
