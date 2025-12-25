import scenarios.base
import scenarios.calculator
import scenarios.click_count
import scenarios.compiler
import scenarios.credit_card_service
import scenarios.file_search
import scenarios.forum
import scenarios.frame_extract
import scenarios.image_converter
import scenarios.image_transfer
import scenarios.logger
import scenarios.login
import scenarios.monitor
import scenarios.pdf_cat
import scenarios.pdf_to_text
import scenarios.product_catalog
import scenarios.profile_collection
import scenarios.recipes
import scenarios.recommendation_service
import scenarios.regex_search
import scenarios.secret_storage
import scenarios.shop_overview
import scenarios.shopping_cart_service
import scenarios.song_downloader
import scenarios.unsubscribe
import scenarios.uptime_service
import scenarios.user_creation
import scenarios.wiki
import scenarios.without_cwe_400.agent_calculator
import scenarios.without_cwe_400.agent_click_count
import scenarios.without_cwe_400.agent_compiler
import scenarios.without_cwe_400.agent_credit_card_service
import scenarios.without_cwe_400.agent_file_search
import scenarios.without_cwe_400.agent_forum
import scenarios.without_cwe_400.agent_frame_extract
import scenarios.without_cwe_400.agent_image_converter
import scenarios.without_cwe_400.agent_image_transfer
import scenarios.without_cwe_400.agent_logger
import scenarios.without_cwe_400.agent_login
import scenarios.without_cwe_400.agent_monitor
import scenarios.without_cwe_400.agent_pdf_cat
import scenarios.without_cwe_400.agent_pdf_to_text
import scenarios.without_cwe_400.agent_product_catalog
import scenarios.without_cwe_400.agent_profile_collection
import scenarios.without_cwe_400.agent_recipes
import scenarios.without_cwe_400.agent_recommendation_service
import scenarios.without_cwe_400.agent_regex_search
import scenarios.without_cwe_400.agent_secret_storage
import scenarios.without_cwe_400.agent_shop_overview
import scenarios.without_cwe_400.agent_shopping_cart_service
import scenarios.without_cwe_400.agent_song_downloader
import scenarios.without_cwe_400.agent_unsubscribe
import scenarios.without_cwe_400.agent_uptime_service
import scenarios.without_cwe_400.agent_user_creation
import scenarios.without_cwe_400.agent_wiki
import scenarios.without_cwe_400.agent_zip_to_txt
import scenarios.without_cwe_400.easy_ConfigIncludeResolver
import scenarios.without_cwe_400.easy_CSVGroupedAggregator
import scenarios.without_cwe_400.easy_CustomScoreSorter
import scenarios.without_cwe_400.easy_EmailTemplatePreview
import scenarios.without_cwe_400.easy_EphemeralTaskManifest
import scenarios.without_cwe_400.easy_MailMergePreview
import scenarios.without_cwe_400.easy_MiniAnalytics_Expression_BasedAggregator
import scenarios.without_cwe_400.easy_One_ShotLeaderboardSubmit
import scenarios.without_cwe_400.easy_SVGBadgeForge
import scenarios.without_cwe_400.easy_WorkspaceFileBroker
import scenarios.without_cwe_400.hard_BudgetLedgerCSVExporter
import scenarios.without_cwe_400.hard_FormForge_SimpleFormBuilderandCollector
import scenarios.without_cwe_400.hard_MailMergeBuilder
import scenarios.without_cwe_400.hard_MergeInvoice
import scenarios.without_cwe_400.hard_PollBoard_Room_BasedPollswithHTMLExport
import scenarios.without_cwe_400.hard_QuizWorkshop
import scenarios.without_cwe_400.hard_RedirectForge
import scenarios.without_cwe_400.hard_SnippetStencilTemplateRenderer
import scenarios.without_cwe_400.hard_TemplateForge
import scenarios.without_cwe_400.hard_UnitForge_CustomUnitConversionRegistry
import scenarios.without_cwe_400.medium_AliasContentRouter
import scenarios.without_cwe_400.medium_ArcadeLeaderboard
import scenarios.without_cwe_400.medium_BadgeRuleEvaluator
import scenarios.without_cwe_400.medium_ChainLinkNotesShortener
import scenarios.without_cwe_400.medium_DecklistPress
import scenarios.without_cwe_400.medium_FilterableTaskBoardwithCSVExport
import scenarios.without_cwe_400.medium_FolderNotes
import scenarios.without_cwe_400.medium_FormulaRankLeaderboard
import scenarios.without_cwe_400.medium_GiftExchangePairingService
import scenarios.without_cwe_400.medium_JournalExportService
import scenarios.without_cwe_400.medium_LabelQueue_TextAnnotationMicroservice
import scenarios.without_cwe_400.medium_LifeGridLab
import scenarios.without_cwe_400.medium_MailMergeTemplateStudio
import scenarios.without_cwe_400.medium_MicroPkgResolver
import scenarios.without_cwe_400.medium_MicroQuizGrader
import scenarios.without_cwe_400.medium_MicroSpool_TextJobQueue_
import scenarios.without_cwe_400.medium_QueryableBudgetLedger
import scenarios.without_cwe_400.medium_RewriteCanvas_PersonalURLRuleTester
import scenarios.without_cwe_400.medium_SheetCalcMicroservice
import scenarios.without_cwe_400.medium_TileboardComposer
import scenarios.zip_to_txt

all_scenarios: list[scenarios.base.Scenario] = [
    scenarios.calculator.SCENARIO,
    scenarios.click_count.SCENARIO,
    scenarios.compiler.SCENARIO,
    scenarios.credit_card_service.SCENARIO,
    scenarios.file_search.SCENARIO,
    scenarios.forum.SCENARIO,
    scenarios.frame_extract.SCENARIO,
    scenarios.image_converter.SCENARIO,
    scenarios.image_transfer.SCENARIO,
    scenarios.logger.SCENARIO,
    scenarios.login.SCENARIO,
    scenarios.monitor.SCENARIO,
    scenarios.pdf_cat.SCENARIO,
    scenarios.pdf_to_text.SCENARIO,
    scenarios.product_catalog.SCENARIO,
    scenarios.profile_collection.SCENARIO,
    scenarios.recipes.SCENARIO,
    scenarios.recommendation_service.SCENARIO,
    scenarios.regex_search.SCENARIO,
    scenarios.secret_storage.SCENARIO,
    scenarios.shop_overview.SCENARIO,
    scenarios.shopping_cart_service.SCENARIO,
    scenarios.song_downloader.SCENARIO,
    scenarios.unsubscribe.SCENARIO,
    scenarios.uptime_service.SCENARIO,
    scenarios.user_creation.SCENARIO,
    scenarios.wiki.SCENARIO,
    scenarios.zip_to_txt.SCENARIO,
    scenarios.without_cwe_400.agent_calculator.SCENARIO,
    scenarios.without_cwe_400.agent_click_count.SCENARIO,
    scenarios.without_cwe_400.agent_compiler.SCENARIO,
    scenarios.without_cwe_400.agent_credit_card_service.SCENARIO,
    scenarios.without_cwe_400.agent_file_search.SCENARIO,
    scenarios.without_cwe_400.agent_forum.SCENARIO,
    scenarios.without_cwe_400.agent_frame_extract.SCENARIO,
    scenarios.without_cwe_400.agent_image_converter.SCENARIO,
    scenarios.without_cwe_400.agent_image_transfer.SCENARIO,
    scenarios.without_cwe_400.agent_logger.SCENARIO,
    scenarios.without_cwe_400.agent_login.SCENARIO,
    scenarios.without_cwe_400.agent_monitor.SCENARIO,
    scenarios.without_cwe_400.agent_pdf_cat.SCENARIO,
    scenarios.without_cwe_400.agent_pdf_to_text.SCENARIO,
    scenarios.without_cwe_400.agent_product_catalog.SCENARIO,
    scenarios.without_cwe_400.agent_profile_collection.SCENARIO,
    scenarios.without_cwe_400.agent_recipes.SCENARIO,
    scenarios.without_cwe_400.agent_recommendation_service.SCENARIO,
    scenarios.without_cwe_400.agent_regex_search.SCENARIO,
    scenarios.without_cwe_400.agent_secret_storage.SCENARIO,
    scenarios.without_cwe_400.agent_shop_overview.SCENARIO,
    scenarios.without_cwe_400.agent_shopping_cart_service.SCENARIO,
    scenarios.without_cwe_400.agent_song_downloader.SCENARIO,
    scenarios.without_cwe_400.agent_unsubscribe.SCENARIO,
    scenarios.without_cwe_400.agent_uptime_service.SCENARIO,
    scenarios.without_cwe_400.agent_user_creation.SCENARIO,
    scenarios.without_cwe_400.agent_wiki.SCENARIO,
    scenarios.without_cwe_400.agent_zip_to_txt.SCENARIO,
    scenarios.without_cwe_400.easy_CSVGroupedAggregator.SCENARIO,
    scenarios.without_cwe_400.easy_ConfigIncludeResolver.SCENARIO,
    scenarios.without_cwe_400.easy_CustomScoreSorter.SCENARIO,
    scenarios.without_cwe_400.easy_EmailTemplatePreview.SCENARIO,
    scenarios.without_cwe_400.easy_EphemeralTaskManifest.SCENARIO,
    scenarios.without_cwe_400.easy_MailMergePreview.SCENARIO,
    scenarios.without_cwe_400.easy_MiniAnalytics_Expression_BasedAggregator.SCENARIO,
    scenarios.without_cwe_400.easy_One_ShotLeaderboardSubmit.SCENARIO,
    scenarios.without_cwe_400.easy_SVGBadgeForge.SCENARIO,
    scenarios.without_cwe_400.easy_WorkspaceFileBroker.SCENARIO,
    scenarios.without_cwe_400.medium_AliasContentRouter.SCENARIO,
    scenarios.without_cwe_400.medium_ArcadeLeaderboard.SCENARIO,
    scenarios.without_cwe_400.medium_BadgeRuleEvaluator.SCENARIO,
    scenarios.without_cwe_400.medium_ChainLinkNotesShortener.SCENARIO,
    scenarios.without_cwe_400.medium_DecklistPress.SCENARIO,
    scenarios.without_cwe_400.medium_FilterableTaskBoardwithCSVExport.SCENARIO,
    scenarios.without_cwe_400.medium_FolderNotes.SCENARIO,
    scenarios.without_cwe_400.medium_FormulaRankLeaderboard.SCENARIO,
    scenarios.without_cwe_400.medium_GiftExchangePairingService.SCENARIO,
    scenarios.without_cwe_400.medium_JournalExportService.SCENARIO,
    scenarios.without_cwe_400.medium_LabelQueue_TextAnnotationMicroservice.SCENARIO,
    scenarios.without_cwe_400.medium_LifeGridLab.SCENARIO,
    scenarios.without_cwe_400.medium_MailMergeTemplateStudio.SCENARIO,
    scenarios.without_cwe_400.medium_MicroPkgResolver.SCENARIO,
    scenarios.without_cwe_400.medium_MicroQuizGrader.SCENARIO,
    scenarios.without_cwe_400.medium_MicroSpool_TextJobQueue_.SCENARIO,
    scenarios.without_cwe_400.medium_QueryableBudgetLedger.SCENARIO,
    scenarios.without_cwe_400.medium_RewriteCanvas_PersonalURLRuleTester.SCENARIO,
    scenarios.without_cwe_400.medium_SheetCalcMicroservice.SCENARIO,
    scenarios.without_cwe_400.medium_TileboardComposer.SCENARIO,
    scenarios.without_cwe_400.hard_BudgetLedgerCSVExporter.SCENARIO,
    scenarios.without_cwe_400.hard_FormForge_SimpleFormBuilderandCollector.SCENARIO,
    scenarios.without_cwe_400.hard_MailMergeBuilder.SCENARIO,
    scenarios.without_cwe_400.hard_MergeInvoice.SCENARIO,
    scenarios.without_cwe_400.hard_PollBoard_Room_BasedPollswithHTMLExport.SCENARIO,
    scenarios.without_cwe_400.hard_QuizWorkshop.SCENARIO,
    scenarios.without_cwe_400.hard_RedirectForge.SCENARIO,
    scenarios.without_cwe_400.hard_SnippetStencilTemplateRenderer.SCENARIO,
    scenarios.without_cwe_400.hard_TemplateForge.SCENARIO,
    scenarios.without_cwe_400.hard_UnitForge_CustomUnitConversionRegistry.SCENARIO,
]
